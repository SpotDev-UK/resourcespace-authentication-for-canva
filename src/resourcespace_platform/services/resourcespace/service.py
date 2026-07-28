"""Facade service wiring fixture and live ResourceSpace backends."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from ...config import DEV_LIKE_ENVIRONMENTS, AppConfig
from ._fixture_backend import (
    _authenticate_fixture_sso,
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
    _is_private_ip,
    _normalize_api_url,
    _slugify,
    canonical_ascii_host,
    normalize_base_url,
)
from ._live_backend import (
    _authenticate_live_tenant,
    _get_live_download_source,
    _list_live_assets,
    _list_live_containers,
    _search_live_containers,
    _validate_live_sessionkey,
)
from ._upload import _upload_live_resource


def _reject_private_tenant_sink(config: AppConfig, *urls: str | None) -> None:
    """Block SSRF to internal addresses for every host the broker will
    actually connect to (tenant base URL and the resolved API URL).

    Runs for every non-fixture mode (the runtime dispatch treats anything that
    is not exactly ``"fixture"`` as live, so the guard must match that, not just
    the literal ``"live"``). ``_is_private_ip`` fails closed on non-resolving
    hosts, and fixture/dev flows use non-resolving demo hostnames, so gating on
    fixture avoids wrongly blocking them. Applies even to configured/allowlisted
    tenants (a mis-set or tampered tenant entry must not become an internal
    request sink).
    """
    if config.resource_space.mode == "fixture":
        return
    for url in urls:
        if not url:
            continue
        host = (urlparse(url).hostname or "").lower()
        if host and _is_private_ip(host):
            raise ResourceSpaceError(
                "FORBIDDEN",
                "This ResourceSpace URL resolves to a private network address.",
                403,
            )


def _tenant_identity(url: str | None) -> tuple[str, str, int] | None:
    """Structured ``(scheme, host, effective_port)`` key for tenant matching.

    A structured key (not a serialised string) avoids IPv6 bracket ambiguity
    (``[2606:4700::1111]:443`` vs the distinct host ``[2606:4700::1111:443]``).
    The host is UTS46-canonicalised, and IP literals are normalised to their
    compressed form, so equivalent spellings match. The port defaults to the
    scheme default, so ``https://host`` and ``https://host:443`` are equivalent.
    Without this a ``https://faß.de`` record would be missed by a
    ``https://xn--fa-hia.de`` request and silently degrade to a generic tenant.
    """
    normalized = normalize_base_url(url)
    if not normalized:
        return None
    parsed = urlparse(normalized)
    scheme = (parsed.scheme or "").lower()
    try:
        host = canonical_ascii_host(parsed.hostname or "")
    except ResourceSpaceError:
        return None
    if not host:
        return None
    try:
        host = ipaddress.ip_address(host).compressed  # normalise IPv4/IPv6 literals
    except ValueError:
        pass  # a domain name, already canonical ASCII
    try:
        explicit_port = parsed.port
    except ValueError:
        return None  # malformed / out-of-range port
    # `is not None`, not `or`: an explicit `:0` must stay 0, distinct from the
    # scheme default, so it cannot falsely match a default-port tenant record.
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    return (scheme, host, port)


def get_configured_tenant(config: AppConfig, base_url: str | None) -> dict[str, Any]:
    normalized = normalize_base_url(base_url)
    if not normalized:
        raise ResourceSpaceError("INVALID_TENANT_URL", "A ResourceSpace URL is required.", 400)

    requested_identity = _tenant_identity(normalized)
    for tenant in config.resource_space.tenants:
        if requested_identity is not None and _tenant_identity(tenant.get("baseUrl")) == requested_identity:
            resolved_base = normalize_base_url(tenant["baseUrl"]) or ""
            resolved_api = _normalize_api_url(resolved_base, tenant.get("apiUrl"))
            # Validate both the base URL and the actual API request sink; a
            # configured apiUrl override must not bypass the private-IP guard.
            _reject_private_tenant_sink(config, resolved_base, resolved_api)
            return {
                **tenant,
                "baseUrl": resolved_base,
                "apiUrl": resolved_api,
            }

    parsed = urlparse(normalized)
    host = requested_identity[1] if requested_identity is not None else ""
    allowed = config.resource_space.allowed_hosts
    host_is_approved = bool(
        host and any(_host_matches_pattern(host, pattern) for pattern in allowed)
    )

    # Development keeps its historical convenience of synthesizing any public
    # tenant when no allowlist is configured. Outside development/test, an
    # unregistered tenant is accepted only under an explicitly configured,
    # approved ResourceSpace hostname suffix.
    if not host_is_approved and (
        config.environment not in DEV_LIKE_ENVIRONMENTS or allowed
    ):
        raise ResourceSpaceError(
            "UNKNOWN_TENANT",
            "This ResourceSpace URL is not in the broker tenant registry or approved hostname suffixes.",
            403,
        )

    # Preserve the SSRF classification for private targets even when another
    # URL property is also invalid (for example an http:// RFC1918 literal).
    _reject_private_tenant_sink(config, normalized)

    # Synthetic tenants cannot opt into alternate schemes, credentials, or
    # ports. Exact registry records remain the explicit escape hatch for custom
    # deployments; the hosted suffix path is deliberately HTTPS/443 only.
    if (
        requested_identity is None
        or requested_identity[0] != "https"
        or requested_identity[2] != 443
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ResourceSpaceError(
            "INVALID_TENANT_URL",
            "Hosted ResourceSpace URLs must use HTTPS on the default port without credentials.",
            400,
        )

    resolved_base = f"https://{host}"
    slug = _slugify(host)
    return {
        "id": f"tenant_{slug}",
        "slug": slug,
        "name": host,
        "baseUrl": resolved_base,
        "apiUrl": _normalize_api_url(resolved_base, None),
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

    def authenticate_with_session_key(
        self,
        *,
        tenant: dict[str, Any],
        session_key: str,
        username: str,
        integration: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate an SSO handoff: validate a ResourceSpace session key and
        build the bridge session. Dispatches fixture/live like the other methods.

        A missing/empty username fails before any upstream call: the RS signed
        call keys identity off ``user``, so a blank or invented username can
        never validate, and the flow must not fabricate an identity.
        """
        if not username or not username.strip():
            raise ResourceSpaceError(
                "SSO_HANDOFF_FAILED",
                "ResourceSpace callback did not provide a username.",
                400,
            )
        if not session_key or not session_key.strip():
            raise ResourceSpaceError(
                "SSO_HANDOFF_FAILED",
                "ResourceSpace callback did not provide a session key.",
                400,
            )
        if self.config.resource_space.mode == "fixture":
            return _authenticate_fixture_sso(tenant, session_key, username)
        return _validate_live_sessionkey(
            tenant,
            session_key,
            username,
            integration=integration,
        )

    def get_session_summary(self, session: dict[str, Any]) -> dict[str, Any]:
        user: dict[str, Any] = {
            "id": session["user"]["id"],
            "username": session["user"]["username"],
            "displayName": session["user"].get("displayName"),
            "role": session["user"].get("role"),
        }
        email = session["user"].get("email")
        if email:
            user["email"] = email
        return {
            "mode": session["upstream"]["mode"],
            "tenant": {
                "id": session["tenant"]["id"],
                "slug": session["tenant"].get("slug"),
                "name": session["tenant"].get("name"),
                "baseUrl": session["tenant"].get("baseUrl"),
            },
            "user": user,
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
