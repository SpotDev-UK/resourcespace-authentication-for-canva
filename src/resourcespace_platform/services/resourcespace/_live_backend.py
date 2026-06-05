"""Live-mode ResourceSpace backend (signed-sessionkey HTTP calls)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from ...config import AppConfig
from ._helpers import (
    SUPPORTED_IMAGE_MIME_TYPES,
    ResourceSpaceError,
    _broker_integration_from_session,
    _build_signed_api_url,
    _decode_collection_container_id,
    _encode_collection_container_id,
    _mime_type_from_extension,
    _pick_asset_description,
    _pick_asset_name,
    _resourcespace_request_headers,
    _sort_collections,
    _to_iso_date,
)


def _parse_jsonish_response(response: httpx.Response) -> Any:
    if response.status_code == 401 or response.status_code == 403:
        raise ResourceSpaceError(
            "UPSTREAM_SESSION_EXPIRED",
            "ResourceSpace session is no longer valid; re-authentication required.",
            401,
        )
    if response.status_code >= 400:
        raise ResourceSpaceError(
            "UPSTREAM_REQUEST_FAILED",
            f"ResourceSpace API request failed with status {response.status_code}.",
            502,
        )
    text = response.text
    try:
        return response.json()
    except ValueError:
        return text


def _fetch_jsonish_sync(url: str, *, integration: str | None = None) -> Any:
    try:
        with httpx.Client(
            timeout=30.0,
            headers=_resourcespace_request_headers(integration),
        ) as client:
            response = client.get(url)
    except httpx.HTTPError as exc:
        raise ResourceSpaceError(
            "UPSTREAM_UNAVAILABLE",
            "ResourceSpace could not be reached.",
            502,
        ) from exc
    return _parse_jsonish_response(response)


def _post_jsonish_sync(
    url: str, data: dict[str, str], *, integration: str | None = None
) -> Any:
    try:
        with httpx.Client(
            timeout=30.0,
            headers=_resourcespace_request_headers(integration),
        ) as client:
            response = client.post(url, data=data)
    except httpx.HTTPError as exc:
        raise ResourceSpaceError(
            "UPSTREAM_UNAVAILABLE",
            "ResourceSpace could not be reached.",
            502,
        ) from exc
    return _parse_jsonish_response(response)


def _authenticate_live_tenant(
    config: AppConfig,
    base_url: str | None,
    username: str,
    password: str,
    *,
    integration: str | None = None,
) -> dict[str, Any]:
    # Imported locally to avoid a circular import: service.py imports from
    # this module at load time, and get_configured_tenant lives there as
    # the facade-level tenant lookup.
    from .service import get_configured_tenant

    tenant = get_configured_tenant(config, base_url)
    result = _post_jsonish_sync(
        tenant["apiUrl"],
        {"function": "login", "username": username, "password": password},
        integration=integration,
    )
    if result in (False, "false", "", None):
        raise ResourceSpaceError("INVALID_CREDENTIALS", "Invalid ResourceSpace credentials.", 401)
    session_key = str(result)
    return {
        "tenant": tenant,
        "user": {
            "id": f"{tenant['id']}:{username.lower()}",
            "username": username,
            "displayName": username,
            "role": "member",
        },
        "upstream": {
            "mode": "live",
            "sessionKey": session_key,
            "authenticatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }


def _build_live_collection_container(
    collection: dict[str, Any], tenant: dict[str, Any], child_count: int = 0
) -> dict[str, Any]:
    return {
        "id": _encode_collection_container_id(collection.get("ref")),
        "type": "CONTAINER",
        "name": collection.get("name") or f"Collection {collection.get('ref')}",
        "containerType": "folder",
        "description": f"Collection {collection.get('ref')}" if tenant.get("rootCollections") else None,
        "numContainers": child_count,
        "access": "read-write",
    }


def _apply_configured_collection_tree(
    tenant: dict[str, Any], collections: list[dict[str, Any]], parent_id: str | None
) -> list[dict[str, Any]]:
    lookup = {str(collection.get("ref")): collection for collection in collections}
    child_map = tenant.get("collectionChildren") or {}
    root_refs = tenant.get("rootCollections") or []

    if root_refs:
        current_ids = (
            [str(ref) for ref in root_refs]
            if parent_id is None
            else [str(ref) for ref in child_map.get(str(parent_id), [])]
        )
        return [
            lookup.get(str(ref), {"ref": ref, "name": f"Collection {ref}"})
            for ref in current_ids
        ]

    if parent_id is not None:
        return []
    return collections


def build_live_search_string(query: str, container_id: str | None) -> str:
    search = (query or "").strip()
    collection_ref = _decode_collection_container_id(container_id) if container_id else None
    if collection_ref and search:
        return f"!collection{collection_ref} {search}"
    if collection_ref:
        return f"!collection{collection_ref}"
    return search


def build_live_asset(record: dict[str, Any]) -> dict[str, Any]:
    extension = str(record.get("file_extension") or record.get("preview_extension") or "jpg").lower()
    mime_type = _mime_type_from_extension(extension)
    thumb_width = int(record.get("thumb_width") or record.get("image_width") or 0) or None
    thumb_height = int(record.get("thumb_height") or record.get("image_height") or 0) or None

    thumb_source: dict[str, Any] | None = None
    if record.get("url_thm"):
        thumb_source = {
            "kind": "proxy",
            "url": record["url_thm"],
            "mimeType": _mime_type_from_extension(record.get("preview_extension") or "jpg"),
            "width": int(record.get("thumb_width") or 0) or None,
            "height": int(record.get("thumb_height") or 0) or None,
        }

    preview_url = record.get("url_pre") or record.get("url_thm")
    preview_source: dict[str, Any] | None = None
    if preview_url:
        preview_source = {
            "kind": "proxy",
            "url": preview_url,
            "mimeType": _mime_type_from_extension(record.get("preview_extension") or "jpg"),
            "width": int(record.get("thumb_width") or 0) or None,
            "height": int(record.get("thumb_height") or 0) or None,
        }

    return {
        "id": str(record.get("ref")),
        "type": "IMAGE",
        "name": _pick_asset_name(record),
        "description": _pick_asset_description(record),
        "mimeType": mime_type,
        "filename": record.get("original_filename") or f"{record.get('ref')}.{extension}",
        "width": thumb_width,
        "height": thumb_height,
        "createdAt": _to_iso_date(record.get("creation_date")),
        "updatedAt": _to_iso_date(record.get("file_modified")),
        "thumbnailSource": thumb_source,
        "previewSource": preview_source,
    }


def normalize_live_asset_page(response: Any) -> dict[str, Any]:
    if isinstance(response, dict):
        total = int(response.get("total", 0) or 0)
        items = response.get("data") if isinstance(response.get("data"), list) else []
    elif isinstance(response, list):
        total = len(response)
        items = response
    else:
        total = 0
        items = []

    mapped = [
        asset
        for asset in (build_live_asset(item) for item in items)
        if asset["mimeType"] in SUPPORTED_IMAGE_MIME_TYPES and asset["thumbnailSource"] is not None
    ]
    return {"items": mapped, "total": total}


def _call_live_api(
    *,
    tenant: dict[str, Any],
    username: str,
    session_key: str,
    params: dict[str, Any],
    integration: str | None = None,
) -> Any:
    url = _build_signed_api_url(
        api_url=tenant["apiUrl"],
        username=username,
        session_key=session_key,
        params=params,
    )
    return _fetch_jsonish_sync(url, integration=integration)


def _list_live_containers(session: dict[str, Any], parent_id: str | None) -> list[dict[str, Any]]:
    collections = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        params={"function": "get_user_collections"},
        integration=_broker_integration_from_session(session),
    )
    current_parent_ref = _decode_collection_container_id(parent_id) if parent_id else None
    scoped = _apply_configured_collection_tree(
        session["tenant"],
        collections if isinstance(collections, list) else [],
        current_parent_ref,
    )
    return [
        _build_live_collection_container(
            collection,
            session["tenant"],
            len((session["tenant"].get("collectionChildren") or {}).get(str(collection.get("ref")), [])),
        )
        for collection in _sort_collections(scoped)
    ]


def _search_live_containers(
    session: dict[str, Any], parent_id: str | None, query: str
) -> list[dict[str, Any]]:
    containers = _list_live_containers(session, parent_id)
    normalized = query.strip().lower()
    return [container for container in containers if normalized in container["name"].lower()]


def _list_live_assets(
    session: dict[str, Any],
    *,
    query: str,
    container_id: str | None,
    offset: int,
    limit: int,
    sort: str,
) -> dict[str, Any]:
    order_by = "title" if sort == "name_asc" else "date"
    sort_direction = "asc" if sort == "updated_asc" else "desc"
    response = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        integration=_broker_integration_from_session(session),
        params={
            "function": "search_get_previews",
            "search": build_live_search_string(query, container_id),
            "order_by": order_by,
            "sort": sort_direction,
            "archive": 0,
            "fetchrows": f"{offset},{limit}",
            "getsizes": "thm,pre",
            "previewext": "jpg",
        },
    )
    return normalize_live_asset_page(response)


def _get_live_download_source(session: dict[str, Any], asset_id: str) -> dict[str, Any]:
    resource = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        params={"function": "get_resource_data", "resource": asset_id},
        integration=_broker_integration_from_session(session),
    )
    if not resource or resource in (False, "false"):
        raise ResourceSpaceError("NOT_FOUND", "Asset not found.", 404)

    extension = resource.get("file_extension") or resource.get("preview_extension") or "jpg"
    mime_type = _mime_type_from_extension(extension)
    if mime_type not in SUPPORTED_IMAGE_MIME_TYPES:
        raise ResourceSpaceError("UNSUPPORTED_FORMAT", "Unsupported asset format.", 409)

    original_url = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        integration=_broker_integration_from_session(session),
        params={
            "function": "get_resource_path",
            "ref": asset_id,
            "extension": extension,
            "page": 1,
            "watermarked": 0,
        },
    )
    if not original_url or original_url in (False, "false"):
        raise ResourceSpaceError("NOT_FOUND", "Asset download URL was not available.", 404)

    return {
        "source": {"kind": "proxy", "url": str(original_url), "mimeType": mime_type},
        "mimeType": mime_type,
        "filename": resource.get("original_filename") or f"{asset_id}.{extension}",
    }
