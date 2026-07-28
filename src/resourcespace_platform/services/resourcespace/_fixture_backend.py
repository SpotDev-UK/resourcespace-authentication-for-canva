"""Fixture-mode ResourceSpace backend (deterministic in-memory data)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...data import fixture_data as fixture
from ._helpers import (
    SUPPORTED_IMAGE_MIME_TYPES,
    ResourceSpaceError,
    _decode_fixture_container_id,
    normalize_base_url,
)


def _authenticate_fixture_tenant(base_url: str | None, username: str, password: str) -> dict[str, Any]:
    tenant = fixture.get_tenant_by_base_url(normalize_base_url(base_url) or "")
    if not tenant:
        raise ResourceSpaceError("UNKNOWN_TENANT", "Unknown fixture tenant.", 403)
    user = fixture.get_user_by_tenant_and_username(tenant["id"], username)
    if not user or user["password"] != password:
        raise ResourceSpaceError("INVALID_CREDENTIALS", "Invalid fixture credentials.", 401)
    return {
        "tenant": tenant,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "displayName": user["displayName"],
            "role": user["role"],
        },
        "upstream": {
            "mode": "fixture",
            "authenticatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }


def _authenticate_fixture_sso(
    tenant: dict[str, Any],
    session_key: str,
    username: str,
) -> dict[str, Any]:
    """Resolve a fixture SSO session key to a fixture user.

    Mirrors the live hosted-login validation: a session key that maps to a
    known user (bound to the tenant the handoff was initiated against) yields a
    session; anything else fails closed.
    """
    user_id = fixture.FIXTURE_SSO_SESSION_KEYS.get(session_key)
    user = fixture.get_user_by_id(user_id) if user_id else None
    if not user:
        raise ResourceSpaceError(
            "UPSTREAM_SESSION_EXPIRED", "Unknown fixture SSO session key.", 401
        )
    fixture_tenant = fixture.get_tenant_by_id(user["tenantId"])
    if not fixture_tenant or normalize_base_url(tenant.get("baseUrl")) != normalize_base_url(
        fixture_tenant["baseUrl"]
    ):
        raise ResourceSpaceError(
            "UPSTREAM_SESSION_EXPIRED", "Fixture SSO session key is not valid for this tenant.", 401
        )
    return {
        "tenant": fixture_tenant,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "displayName": user["displayName"],
            "role": user["role"],
        },
        "upstream": {
            "mode": "fixture",
            "authenticatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }


def _build_fixture_container(container: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"fixture:{container['id']}",
        "type": "CONTAINER",
        "name": container["name"],
        "containerType": "folder",
        "description": fixture.get_container_path(container["id"]),
        "numContainers": len(fixture.list_child_containers(container["tenantId"], container["id"])),
        "access": "read-only",
    }


def _build_fixture_asset(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": asset["id"],
        "type": "IMAGE",
        "name": asset["title"],
        "description": asset["summary"],
        "mimeType": asset["mimeType"],
        "filename": asset["filename"],
        "width": asset["width"],
        "height": asset["height"],
        "createdAt": asset["createdAt"],
        "updatedAt": asset["updatedAt"],
        "thumbnailSource": {
            "kind": "fixture",
            "assetId": asset["id"],
            "variant": "thumbnail",
            "mimeType": "image/svg+xml",
            "width": 480,
            "height": 320,
        },
        "previewSource": {
            "kind": "fixture",
            "assetId": asset["id"],
            "variant": "preview",
            "mimeType": asset["mimeType"],
            "width": asset["width"],
            "height": asset["height"],
        },
    }


def _list_fixture_containers(session: dict[str, Any], parent_id: str | None) -> list[dict[str, Any]]:
    tenant_id = session["tenant"]["id"]
    raw_parent_id = _decode_fixture_container_id(parent_id) if parent_id else None
    return [
        _build_fixture_container(container)
        for container in fixture.list_child_containers(tenant_id, raw_parent_id)
    ]


def _search_fixture_containers(
    session: dict[str, Any], parent_id: str | None, query: str
) -> list[dict[str, Any]]:
    containers = _list_fixture_containers(session, parent_id)
    normalized = query.strip().lower()
    return [container for container in containers if normalized in container["name"].lower()]


def _list_fixture_assets(
    session: dict[str, Any],
    *,
    query: str,
    container_id: str | None,
    offset: int,
    limit: int,
    sort: str,
) -> dict[str, Any]:
    user = fixture.get_user_by_id(session["user"]["id"])
    raw_container_id = _decode_fixture_container_id(container_id) if container_id else None
    results = fixture.sort_assets(
        fixture.search_visible_assets(user, query=query, container_id=raw_container_id),
        sort,
    )
    visible = [asset for asset in results if asset["mimeType"] in SUPPORTED_IMAGE_MIME_TYPES]
    slice_ = visible[offset : offset + limit]
    return {"items": [_build_fixture_asset(asset) for asset in slice_], "total": len(visible)}


def _get_fixture_download_source(session: dict[str, Any], asset_id: str) -> dict[str, Any]:
    user = fixture.get_user_by_id(session["user"]["id"])
    asset = fixture.get_asset_by_id(asset_id)
    if not asset or asset["tenantId"] != session["tenant"]["id"]:
        raise ResourceSpaceError("NOT_FOUND", "Asset not found.", 404)
    visible_assets = fixture.search_visible_assets(user, query=asset["title"])
    if not any(entry["id"] == asset_id for entry in visible_assets):
        raise ResourceSpaceError("FORBIDDEN", "This asset is not available to the current user.", 403)
    if not fixture.is_asset_importable(asset):
        raise ResourceSpaceError(
            "UNSUPPORTED_FORMAT", "This asset format is not importable in Phase 1.", 409
        )
    return {
        "source": {
            "kind": "fixture",
            "assetId": asset_id,
            "variant": "full",
            "mimeType": asset["mimeType"],
            "width": asset["width"],
            "height": asset["height"],
        },
        "mimeType": asset["mimeType"],
        "filename": asset["filename"],
    }
