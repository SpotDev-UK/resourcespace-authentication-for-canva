"""Tests for trusted-proxy-gated client IP extraction."""
from __future__ import annotations

from dataclasses import dataclass, field

import pytest
from starlette.requests import Request
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from resourcespace_platform.config import create_config
from resourcespace_platform.http_utils import client_host, pseudonymize_client_ip, resolve_client_host
from resourcespace_platform.trusted_proxy import (
    client_ip_from_x_forwarded_for,
    host_matches_trusted_proxy,
)


@dataclass
class _FakeClient:
    host: str


@dataclass
class _FakeRequest:
    client: _FakeClient | None
    headers: dict[str, str] = field(default_factory=dict)
    app: object | None = None


def test_host_matches_trusted_proxy_cidr() -> None:
    assert host_matches_trusted_proxy("10.1.2.3", ["10.0.0.0/8"])
    assert not host_matches_trusted_proxy("203.0.113.1", ["10.0.0.0/8"])
    assert host_matches_trusted_proxy("100.64.1.2", ["100.64.0.0/10"])


def test_production_defaults_include_railway_cgnat() -> None:
    config = create_config({"APP_ENV": "production"})
    assert "100.64.0.0/10" in config.trusted_proxy_hosts
    assert config.client_ip_header == "x-real-ip"


def test_pseudonymize_client_ip_is_stable_and_not_raw() -> None:
    key = "test-client-ip-log-key"
    assert pseudonymize_client_ip("203.0.113.10", key) == pseudonymize_client_ip(
        "203.0.113.10", key
    )
    assert pseudonymize_client_ip("203.0.113.10", key) != pseudonymize_client_ip(
        "203.0.113.11", key
    )
    assert pseudonymize_client_ip("203.0.113.10", "other-key") != pseudonymize_client_ip(
        "203.0.113.10", key
    )
    assert pseudonymize_client_ip("", key) is None
    assert pseudonymize_client_ip("unknown", key) is None


def test_header_present_but_untrusted_peer_is_diagnosable() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "10.0.0.0/8",
        }
    )
    scope = _http_scope(
        client=("203.0.113.5", 12345),
        headers=[(b"x-real-ip", b"1.2.3.4")],
    )
    resolution = resolve_client_host(Request(scope), config)
    assert resolution.header_present is True
    assert resolution.header_trusted is False
    assert resolution.host == "203.0.113.5"


def test_log_context_includes_raw_transport_peer_when_diagnostics_enabled() -> None:
    config = create_config(
        {
            "APP_ENV": "staging",
            "CLIENT_IP_LOG_DIAGNOSTICS": "true",
            "CLIENT_IP_LOG_KEY": "diag-test-key",
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "100.64.0.0/10",
        }
    )
    resolution = resolve_client_host(
        Request(_http_scope(client=("100.64.1.2", 1), headers=[(b"x-real-ip", b"203.0.113.10")])),
        config,
    )
    context = resolution.log_context(config=config)
    assert context["transportPeer"] == "100.64.1.2"
    assert "transportPeerHash" in context


def _production_grade_config(**overrides: str) -> dict[str, str]:
    from cryptography.fernet import Fernet

    env: dict[str, str] = {
        "CANVA_REQUEST_VERIFICATION_MODE": "required",
        "CANVA_CLIENT_SECRET": "c2VjcmV0",
        "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
        "OAUTH_CLIENT_ID": "real-canva-client",
        "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
        "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
        "STORAGE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "RESOURCE_SPACE_TENANTS_JSON": '[{"id":"acme","baseUrl":"https://acme.example.com"}]',
    }
    env.update(overrides)
    return env


@pytest.mark.parametrize("app_env", ["production", "prod", "live", "Production"])
def test_production_aliases_reject_client_ip_log_diagnostics(app_env: str) -> None:
    from resourcespace_platform.config import ConfigValidationError, validate_config_for_environment

    config = create_config(
        _production_grade_config(
            APP_ENV=app_env,
            CLIENT_IP_LOG_DIAGNOSTICS="true",
        )
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "CLIENT_IP_LOG_DIAGNOSTICS" in str(info.value)


def test_staging_allows_client_ip_log_diagnostics() -> None:
    from resourcespace_platform.config import validate_config_for_environment

    config = create_config(
        _production_grade_config(
            APP_ENV="staging",
            CLIENT_IP_LOG_DIAGNOSTICS="true",
        )
    )
    validate_config_for_environment(config)


def test_production_rejects_client_ip_log_diagnostics() -> None:
    from resourcespace_platform.config import ConfigValidationError, validate_config_for_environment

    config = create_config(
        _production_grade_config(
            APP_ENV="production",
            CLIENT_IP_LOG_DIAGNOSTICS="true",
        )
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "CLIENT_IP_LOG_DIAGNOSTICS" in str(info.value)


def _http_scope(
    *,
    client: tuple[str, int],
    headers: list[tuple[bytes, bytes]],
) -> dict:
    return {
        "type": "http",
        "asgi": {"spec_version": "2.3", "version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/oauth/authorise",
        "raw_path": b"/oauth/authorise",
        "query_string": b"",
        "headers": headers,
        "client": client,
        "server": ("testserver", 80),
        "state": {},
    }


@pytest.mark.asyncio
async def test_proxy_headers_middleware_hides_transport_peer_from_diagnostics() -> None:
    """Uvicorn's middleware rewrites scope.client from X-Forwarded-For first."""
    config = create_config(
        {
            "APP_ENV": "production",
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "100.64.0.0/10",
        }
    )
    captured: dict[str, object] = {}

    async def app(scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        captured["resolution"] = resolve_client_host(Request(scope), config)

    middleware = ProxyHeadersMiddleware(app, trusted_hosts="100.64.0.0/10")
    scope = _http_scope(
        client=("100.64.1.2", 12345),
        headers=[
            (b"x-real-ip", b"203.0.113.10"),
            (b"x-forwarded-for", b"203.0.113.10"),
        ],
    )

    async def receive() -> dict[str, str]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(_message) -> None:  # type: ignore[no-untyped-def]
        return None

    await middleware(scope, receive, send)
    resolution = captured["resolution"]
    assert resolution.transport_peer == "203.0.113.10"
    assert resolution.header_trusted is False
    assert resolution.host == "203.0.113.10"
    assert resolution.header_present is True


def test_resolve_client_host_without_proxy_middleware() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "100.64.0.0/10",
        }
    )
    scope = _http_scope(
        client=("100.64.1.2", 12345),
        headers=[(b"x-real-ip", b"203.0.113.10"), (b"x-forwarded-for", b"203.0.113.10")],
    )
    resolution = resolve_client_host(Request(scope), config)
    assert resolution.transport_peer == "100.64.1.2"
    assert resolution.host == "203.0.113.10"
    assert resolution.header_trusted is True
    assert resolution.header_present is True
    assert resolution.log_context(config=config)["transportPeerHash"] != resolution.log_context(
        config=config
    )["resolvedClientHostHash"]


def test_client_host_honours_header_from_railway_cgnat_peer() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "100.64.0.0/10",
        }
    )
    scope = {"type": "http", "headers": [], "client": ("100.64.1.2", 1234)}
    request = Request(scope)
    request._headers = {"x-real-ip": "203.0.113.10"}  # type: ignore[attr-defined]
    assert client_host(request, config) == "203.0.113.10"


def test_client_host_honours_header_only_from_trusted_proxy() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "10.0.0.0/8",
        }
    )
    scope = {"type": "http", "headers": [], "client": ("10.0.0.5", 1234)}
    request = Request(scope)
    request._headers = {"x-real-ip": "203.0.113.10"}  # type: ignore[attr-defined]
    assert client_host(request, config) == "203.0.113.10"


def test_x_forwarded_for_selects_rightmost_untrusted_hop() -> None:
    trusted = ["10.0.0.0/8"]
    assert client_ip_from_x_forwarded_for("203.0.113.10", trusted) == "203.0.113.10"
    assert (
        client_ip_from_x_forwarded_for("1.2.3.4, 203.0.113.10", trusted)
        == "203.0.113.10"
    )
    assert (
        client_ip_from_x_forwarded_for("203.0.113.10, 10.0.0.5", trusted)
        == "203.0.113.10"
    )
    assert client_ip_from_x_forwarded_for("10.0.0.5, 10.0.0.6", trusted) is None


def test_client_host_x_forwarded_for_ignores_spoofed_leftmost_hop() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CLIENT_IP_HEADER": "x-forwarded-for",
            "TRUSTED_PROXY_HOSTS": "10.0.0.0/8",
        }
    )
    scope = {"type": "http", "headers": [], "client": ("10.0.0.5", 1234)}
    request = Request(scope)
    request._headers = {  # type: ignore[attr-defined]
        "x-forwarded-for": "1.2.3.4, 203.0.113.10",
    }
    assert client_host(request, config) == "203.0.113.10"


def test_client_host_ignores_spoofed_header_on_direct_connection() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "10.0.0.0/8",
        }
    )
    scope = {"type": "http", "headers": [], "client": ("203.0.113.5", 1234)}
    request = Request(scope)
    request._headers = {"x-real-ip": "1.2.3.4"}  # type: ignore[attr-defined]
    assert client_host(request, config) == "203.0.113.5"


def test_validator_rejects_client_ip_header_without_trusted_proxies() -> None:
    from resourcespace_platform.config import ConfigValidationError, validate_config_for_environment
    from cryptography.fernet import Fernet

    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": "c2VjcmV0",
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
            "STORAGE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
            "RESOURCE_SPACE_TENANTS_JSON": '[{"id":"acme","baseUrl":"https://acme.example.com"}]',
            "CLIENT_IP_HEADER": "x-real-ip",
            "TRUSTED_PROXY_HOSTS": "",
        }
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "TRUSTED_PROXY_HOSTS" in str(info.value)
