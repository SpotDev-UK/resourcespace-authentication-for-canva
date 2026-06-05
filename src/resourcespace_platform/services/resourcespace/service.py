"""Facade service wiring fixture and live ResourceSpace backends."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from ...config import AppConfig
from ._fixture_backend import (
    _authenticate_fixture_tenant,
    _get_fixture_download_source,
    _list_fixture_assets,
    _list_fixture_containers,
    _search_fixture_containers,
)
from ._helpers import (
    ResourceSpaceError,
    _decode_collection_container_id,
    _host_matches_pattern,
    _normalize_api_url,
    _slugify,
    normalize_base_url,
)
from ._live_backend import (
    _authenticate_live_tenant,
    _get_live_download_source,
    _list_live_assets,
    _list_live_containers,
    _search_live_containers,
)
from ._upload import _upload_live_resource


def get_configured_tenant(config: AppConfig, base_url: str | None) -> dict[str, Any]:
    normalized = normalize_base_url(base_url)
    if not normalized:
        raise ResourceSpaceError("INVALID_TENANT_URL", "A ResourceSpace URL is required.", 400)

    for tenant in config.resource_space.tenants:
        if normalize_base_url(tenant.get("baseUrl")) == normalized:
            return {
                **tenant,
                "baseUrl": normalize_base_url(tenant["baseUrl"]),
                "apiUrl": _normalize_api_url(
                    normalize_base_url(tenant["baseUrl"]) or "",
                    tenant.get("apiUrl"),
                ),
            }

    host = (urlparse(normalized).hostname or "").lower()
    allowed = config.resource_space.allowed_hosts
    if allowed and not any(_host_matches_pattern(host, pattern) for pattern in allowed):
        raise ResourceSpaceError(
            "UNKNOWN_TENANT",
            "This ResourceSpace URL is not approved for the hosted Phase 1 rollout.",
            403,
        )

    slug = _slugify(host)
    return {
        "id": f"tenant_{slug}",
        "slug": slug,
        "name": host,
        "baseUrl": normalized,
        "apiUrl": _normalize_api_url(normalized, None),
        "rootCollections": [],
        "collectionChildren": {},
    }


@dataclass
class ResourceSpaceService:
    config: AppConfig

    def authenticate(
        self,
        *,
        tenant_base_url: str | None,
        username: str,
        password: str,
        integration: str | None = None,
    ) -> dict[str, Any]:
        if self.config.resource_space.mode == "fixture":
            return _authenticate_fixture_tenant(tenant_base_url, username, password)
        return _authenticate_live_tenant(
            self.config,
            tenant_base_url,
            username,
            password,
            integration=integration,
        )

    def get_session_summary(self, session: dict[str, Any]) -> dict[str, Any]:
        return {
            "mode": session["upstream"]["mode"],
            "tenant": {
                "id": session["tenant"]["id"],
                "slug": session["tenant"].get("slug"),
                "name": session["tenant"].get("name"),
                "baseUrl": session["tenant"].get("baseUrl"),
            },
            "user": {
                "id": session["user"]["id"],
                "username": session["user"]["username"],
                "displayName": session["user"].get("displayName"),
                "role": session["user"].get("role"),
            },
        }

    def list_containers(self, session: dict[str, Any], parent_id: str | None) -> list[dict[str, Any]]:
        if session["upstream"]["mode"] == "fixture":
            return _list_fixture_containers(session, parent_id)
        return _list_live_containers(session, parent_id)

    def search_containers(
        self, session: dict[str, Any], parent_id: str | None, query: str
    ) -> list[dict[str, Any]]:
        if session["upstream"]["mode"] == "fixture":
            return _search_fixture_containers(session, parent_id, query)
        return _search_live_containers(session, parent_id, query)

    def list_assets(self, session: dict[str, Any], **options: Any) -> dict[str, Any]:
        if session["upstream"]["mode"] == "fixture":
            return _list_fixture_assets(session, **options)
        return _list_live_assets(session, **options)

    def get_download_source(self, session: dict[str, Any], asset_id: str) -> dict[str, Any]:
        if session["upstream"]["mode"] == "fixture":
            return _get_fixture_download_source(session, asset_id)
        return _get_live_download_source(session, asset_id)

    def upload_resource(
        self,
        *,
        session: dict[str, Any],
        container_id: str,
        source_url: str,
        title: str | None,
    ) -> dict[str, Any]:
        collection_ref = _decode_collection_container_id(container_id)
        if not collection_ref:
            raise ResourceSpaceError(
                "INVALID_REQUEST",
                "Unsupported container id for upload.",
                400,
            )
        if session["upstream"]["mode"] == "fixture":
            raise ResourceSpaceError(
                "FORBIDDEN",
                "Uploads are not available against fixture tenants.",
                403,
            )
        return _upload_live_resource(
            session,
            config=self.config,
            collection_ref=collection_ref,
            source_url=source_url,
            title=title,
        )

    def map_error(self, error: Exception) -> ResourceSpaceError:
        if isinstance(error, ResourceSpaceError):
            return error
        if isinstance(error, (httpx.HTTPError, ConnectionError, TimeoutError)):
            return ResourceSpaceError(
                "UPSTREAM_UNAVAILABLE", "ResourceSpace could not be reached.", 502
            )
        return ResourceSpaceError(
            "INTERNAL_ERROR", "Unexpected ResourceSpace integration failure.", 500
        )


def create_resourcespace_service(config: AppConfig) -> ResourceSpaceService:
    return ResourceSpaceService(config=config)
