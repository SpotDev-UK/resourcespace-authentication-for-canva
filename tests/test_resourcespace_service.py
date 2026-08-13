"""ResourceSpace service helper tests.

Mirrors the Node `resourcespace-service.test.js` suite.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest

from resourcespace_platform.config import create_config
from resourcespace_platform.services.asset_service import AssetService
from resourcespace_platform.services.resourcespace import (
    ResourceSpaceError,
    build_live_asset,
    build_live_search_string,
    create_resourcespace_service,
    get_configured_tenant,
    normalize_live_asset_page,
)
from resourcespace_platform.services.resourcespace._helpers import (
    RESOURCE_SPACE_CANVA_INTEGRATION,
    RESOURCE_SPACE_CANVA_USER_AGENT,
    _host_matches_pattern,
    _host_matches_strict,
    _is_private_ip,
    canonical_ascii_host,
    pin_request,
    resolve_pinned_addresses,
    resolve_pinned_ip,
)
from resourcespace_platform.services.resourcespace._upload import _validate_export_url
from resourcespace_platform.services.resourcespace.service import _tenant_identity
from resourcespace_platform.services.resourcespace._live_backend import (
    _authenticate_live_tenant,
    _fetch_jsonish_sync,
)
from resourcespace_platform.services.resourcespace._upload import _post_multipart_live_api


def _patch_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force host resolution to a fixed public IP.

    The live-mode SSRF guard (``_is_private_ip`` in ``_helpers``) fails closed
    on non-resolving hosts. Tests that use placeholder hostnames such as
    ``curated.resourcespace.example.com`` (which do not resolve) must patch DNS
    so those hosts pass the guard rather than being rejected as unsafe.
    """

    def _fake_getaddrinfo(host: str, *_args: Any, **_kwargs: Any) -> list[Any]:
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _fake_getaddrinfo,
    )


def test_get_configured_tenant_resolves_explicit_tenants_and_allowlisted_hosts() -> None:
    config = create_config(
        {
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [
                    {
                        "id": "tenant_curated",
                        "slug": "curated",
                        "name": "Curated UAT",
                        "baseUrl": "https://curated.resourcespace.example.com",
                        "apiUrl": "https://api.curated.resourcespace.example.com/",
                    }
                ]
            ),
        }
    )

    configured = get_configured_tenant(
        config, "https://curated.resourcespace.example.com/"
    )
    assert configured["id"] == "tenant_curated"
    assert configured["apiUrl"] == "https://api.curated.resourcespace.example.com/"

    allowlisted = get_configured_tenant(
        config, "https://brand.resourcespace.example.com/path/to/app"
    )
    assert allowlisted["id"] == "tenant_brand-resourcespace-example-com"
    assert allowlisted["baseUrl"] == "https://brand.resourcespace.example.com"
    assert allowlisted["apiUrl"] == "https://brand.resourcespace.example.com/api/"


def test_get_configured_tenant_strips_query_and_fragment_from_tenant_url() -> None:
    config = create_config({"RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com"})

    configured = get_configured_tenant(
        config, "https://brand.resourcespace.example.com/pages/view?page=42#section"
    )

    assert configured["baseUrl"] == "https://brand.resourcespace.example.com"
    assert configured["apiUrl"] == "https://brand.resourcespace.example.com/api/"


def test_get_configured_tenant_rejects_non_allowlisted_hosts() -> None:
    config = create_config({"RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com"})
    with pytest.raises(ResourceSpaceError) as excinfo:
        get_configured_tenant(config, "https://example.org")
    assert excinfo.value.code == "UNKNOWN_TENANT"


def test_production_synthesizes_tenant_under_approved_resourcespace_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_public_dns(monkeypatch)
    config = create_config(
        {
            "APP_ENV": "production",
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.com",
            "RESOURCE_SPACE_TENANTS_JSON": "[]",
        }
    )

    tenant = get_configured_tenant(
        config, "https://SpotDev.Free.ResourceSpace.com:443/login.php"
    )

    assert tenant["id"] == "tenant_spotdev-free-resourcespace-com"
    assert tenant["baseUrl"] == "https://spotdev.free.resourcespace.com"
    assert tenant["apiUrl"] == "https://spotdev.free.resourcespace.com/api/"


@pytest.mark.parametrize(
    "tenant_url",
    [
        "https://resourcespace.com.attacker.example",
        "https://evilresourcespace.com",
        "https://spotdev.free.resourcespace.com.attacker.example",
    ],
)
def test_production_approved_suffix_rejects_hostname_lookalikes(tenant_url: str) -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.com",
            "RESOURCE_SPACE_TENANTS_JSON": "[]",
        }
    )

    with pytest.raises(ResourceSpaceError) as excinfo:
        get_configured_tenant(config, tenant_url)

    assert excinfo.value.code == "UNKNOWN_TENANT"


@pytest.mark.parametrize(
    "tenant_url",
    [
        "http://spotdev.free.resourcespace.com",
        "https://spotdev.free.resourcespace.com:8443",
        "https://user@spotdev.free.resourcespace.com",
    ],
)
def test_production_approved_suffix_requires_https_default_port_without_credentials(
    tenant_url: str,
) -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "RESOURCE_SPACE_MODE": "fixture",
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.com",
            "RESOURCE_SPACE_TENANTS_JSON": "[]",
        }
    )

    with pytest.raises(ResourceSpaceError) as excinfo:
        get_configured_tenant(config, tenant_url)

    assert excinfo.value.code == "INVALID_TENANT_URL"


def test_production_exact_registry_tenant_does_not_need_hosted_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_public_dns(monkeypatch)
    config = create_config(
        {
            "APP_ENV": "production",
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [{"id": "custom", "baseUrl": "https://dam.customer.example"}]
            ),
        }
    )

    tenant = get_configured_tenant(config, "https://dam.customer.example/login.php")

    assert tenant["id"] == "custom"
    assert tenant["baseUrl"] == "https://dam.customer.example"


def test_production_approved_suffix_still_rejects_private_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("10.0.0.9", 0))],
    )
    config = create_config(
        {
            "APP_ENV": "production",
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.com",
            "RESOURCE_SPACE_TENANTS_JSON": "[]",
        }
    )

    with pytest.raises(ResourceSpaceError) as excinfo:
        get_configured_tenant(config, "https://spotdev.free.resourcespace.com")

    assert excinfo.value.code == "FORBIDDEN"


def test_get_configured_tenant_rejects_private_ip_in_live_mode() -> None:
    # Literal IPs resolve deterministically without DNS. Cover loopback,
    # link-local (cloud metadata) and RFC1918 private ranges.
    config = create_config({"RESOURCE_SPACE_MODE": "live"})
    for host in ("https://169.254.169.254", "https://127.0.0.1", "http://10.0.0.5"):
        with pytest.raises(ResourceSpaceError) as excinfo:
            get_configured_tenant(config, host)
        assert excinfo.value.code == "FORBIDDEN", host
        assert excinfo.value.status_code == 403


def test_get_configured_tenant_rejects_private_apiurl_override_in_live_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The configured baseUrl resolves public, but the apiUrl override points at
    # a private host. The actual request sink must still be rejected.
    def _fake_getaddrinfo(host: str, *_args: Any, **_kwargs: Any) -> list[Any]:
        if host == "api.internal":
            return [(2, 1, 6, "", ("10.0.0.9", 0))]
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _fake_getaddrinfo,
    )
    config = create_config(
        {
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [
                    {
                        "id": "tenant_curated",
                        "slug": "curated",
                        "name": "Curated",
                        "baseUrl": "https://curated.resourcespace.example.com",
                        "apiUrl": "https://api.internal/",
                    }
                ]
            ),
        }
    )
    with pytest.raises(ResourceSpaceError) as excinfo:
        get_configured_tenant(config, "https://curated.resourcespace.example.com")
    assert excinfo.value.code == "FORBIDDEN"


def test_get_configured_tenant_allows_private_host_in_fixture_mode() -> None:
    # The guard is gated on live mode: fixture/dev demo hostnames (which may not
    # resolve, or may be loopback) must not be blocked.
    config = create_config({"RESOURCE_SPACE_MODE": "fixture"})
    tenant = get_configured_tenant(config, "https://127.0.0.1")
    assert tenant["baseUrl"] == "https://127.0.0.1"


def test_build_live_search_string_scopes_search_to_collections() -> None:
    assert build_live_search_string("", None) == ""
    assert build_live_search_string("hero", None) == "hero"
    assert build_live_search_string("", "collection:42") == "!collection42"
    assert build_live_search_string("hero banner", "collection:42") == "!collection42 hero banner"


def test_build_live_asset_maps_previews_and_metadata() -> None:
    asset = build_live_asset(
        {
            "ref": 101,
            "title": "Homepage Hero",
            "original_filename": "homepage-hero.png",
            "file_extension": "png",
            "preview_extension": "jpg",
            "thumb_width": 640,
            "thumb_height": 360,
            "image_width": 2400,
            "image_height": 1350,
            "creation_date": "2026-04-10T10:00:00Z",
            "file_modified": "2026-04-11T12:30:00Z",
            "url_thm": "https://assets.example.com/hero-thm.jpg",
            "url_pre": "https://assets.example.com/hero-pre.jpg",
        }
    )

    assert asset["id"] == "101"
    assert asset["mimeType"] == "image/png"
    assert asset["thumbnailSource"]["url"] == "https://assets.example.com/hero-thm.jpg"
    assert asset["previewSource"]["url"] == "https://assets.example.com/hero-pre.jpg"
    assert asset["width"] == 640
    assert asset["height"] == 360


def test_normalize_live_asset_page_keeps_supported_and_drops_unsupported() -> None:
    page = normalize_live_asset_page(
        {
            "total": 3,
            "data": [
                {
                    "ref": 101,
                    "title": "Keep Me",
                    "original_filename": "keep-me.png",
                    "file_extension": "png",
                    "preview_extension": "jpg",
                    "thumb_width": 640,
                    "thumb_height": 360,
                    "url_thm": "https://assets.example.com/keep-me-thm.jpg",
                },
                {
                    "ref": 102,
                    "title": "Unsupported TIFF",
                    "original_filename": "unsupported.tiff",
                    "file_extension": "tiff",
                    "preview_extension": "jpg",
                    "thumb_width": 640,
                    "thumb_height": 360,
                    "url_thm": "https://assets.example.com/unsupported-thm.jpg",
                },
                {
                    "ref": 103,
                    "title": "Missing Thumbnail",
                    "original_filename": "missing-thumb.jpg",
                    "file_extension": "jpg",
                },
            ],
        }
    )

    assert page["total"] == 3
    assert len(page["items"]) == 1
    assert page["items"][0]["id"] == "101"


def test_live_api_get_uses_resourcespace_canva_user_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        status_code = 200
        text = '{"ok": true}'

        def json(self) -> dict[str, bool]:
            return {"ok": True}

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def get(self, url: str, **kwargs: Any) -> FakeResponse:
            captured["url"] = url
            captured["req_headers"] = kwargs.get("headers")
            captured["extensions"] = kwargs.get("extensions")
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )
    _patch_public_dns(monkeypatch)

    assert _fetch_jsonish_sync(
        "https://assets.example.com/api/?function=get_user_collections",
        integration=RESOURCE_SPACE_CANVA_INTEGRATION,
    ) == {"ok": True}
    assert captured["client_kwargs"]["headers"]["User-Agent"] == RESOURCE_SPACE_CANVA_USER_AGENT
    # Pinning replaces the request host with a resolved IP; the original host
    # is preserved for the TLS SNI check and the Host header instead.
    assert captured["req_headers"]["Host"] == "assets.example.com"
    assert captured["extensions"]["sni_hostname"] == "assets.example.com"
    # Environment proxies are disabled so a CONNECT tunnel cannot verify TLS
    # against the pinned IP instead of the SNI hostname.
    assert captured["client_kwargs"]["trust_env"] is False


def test_live_api_get_omits_canva_user_agent_without_trusted_canva_integration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        status_code = 200
        text = '{"ok": true}'

        def json(self) -> dict[str, bool]:
            return {"ok": True}

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def get(self, _url: str, **_kwargs: Any) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )
    _patch_public_dns(monkeypatch)

    assert _fetch_jsonish_sync(
        "https://assets.example.com/api/?function=get_user_collections",
        integration="partner-integration",
    ) == {"ok": True}
    assert captured["client_kwargs"]["headers"] == {}


def test_live_login_uses_post_body_and_canva_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        status_code = 200
        text = "session-api-key"

        def json(self) -> Any:
            raise ValueError

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def get(self, _url: str) -> FakeResponse:
            raise AssertionError("login must not use GET")

        def post(self, url: str, **kwargs: Any) -> FakeResponse:
            captured["url"] = url
            captured["post_kwargs"] = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )
    _patch_public_dns(monkeypatch)
    config = create_config(
        {
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [
                    {
                        "id": "tenant_curated",
                        "slug": "curated",
                        "name": "Curated UAT",
                        "baseUrl": "https://curated.resourcespace.example.com",
                        "apiUrl": "https://api.curated.resourcespace.example.com/",
                    }
                ]
            ),
        }
    )

    session = _authenticate_live_tenant(
        config,
        "https://curated.resourcespace.example.com",
        "alice@example.com",
        "secret-password",
        integration=RESOURCE_SPACE_CANVA_INTEGRATION,
    )

    # Pinning replaces the request host with a resolved IP; the original host
    # is preserved for the TLS SNI check and the Host header instead.
    assert "93.184.216.34" in captured["url"]
    assert captured["post_kwargs"]["headers"]["Host"] == "api.curated.resourcespace.example.com"
    assert captured["post_kwargs"]["extensions"]["sni_hostname"] == "api.curated.resourcespace.example.com"
    assert "secret-password" not in captured["url"]
    assert "alice%40example.com" not in captured["url"]
    assert captured["post_kwargs"]["data"] == {
        "query": urlencode(
            {
                "function": "login",
                "username": "alice@example.com",
                "password": "secret-password",
            }
        )
    }
    assert captured["client_kwargs"]["headers"]["User-Agent"] == RESOURCE_SPACE_CANVA_USER_AGENT
    assert session["upstream"]["sessionKey"] == "session-api-key"
    assert session["user"]["username"] == "alice@example.com"


def test_live_login_omits_canva_user_agent_without_trusted_canva_integration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        status_code = 200
        text = "session-api-key"

        def json(self) -> Any:
            raise ValueError

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def post(self, url: str, **kwargs: Any) -> FakeResponse:
            captured["url"] = url
            captured["post_kwargs"] = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )
    _patch_public_dns(monkeypatch)
    config = create_config(
        {
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [
                    {
                        "id": "tenant_curated",
                        "slug": "curated",
                        "name": "Curated UAT",
                        "baseUrl": "https://curated.resourcespace.example.com",
                        "apiUrl": "https://api.curated.resourcespace.example.com/",
                    }
                ]
            ),
        }
    )

    session = _authenticate_live_tenant(
        config,
        "https://curated.resourcespace.example.com",
        "alice@example.com",
        "secret-password",
        integration="partner-integration",
    )

    # Pinning replaces the request host with a resolved IP; the original host
    # is preserved for the TLS SNI check and the Host header instead.
    assert "93.184.216.34" in captured["url"]
    assert captured["post_kwargs"]["headers"]["Host"] == "api.curated.resourcespace.example.com"
    assert captured["post_kwargs"]["extensions"]["sni_hostname"] == "api.curated.resourcespace.example.com"
    assert "secret-password" not in captured["url"]
    assert captured["post_kwargs"]["data"] == {
        "query": urlencode(
            {
                "function": "login",
                "username": "alice@example.com",
                "password": "secret-password",
            }
        )
    }
    assert captured["client_kwargs"]["headers"] == {}
    assert session["upstream"]["sessionKey"] == "session-api-key"


def test_live_login_invalid_credentials_error_is_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        status_code = 200
        text = "false"

        def json(self) -> bool:
            return False

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def get(self, _url: str) -> FakeResponse:
            raise AssertionError("login must not use GET")

        def post(self, _url: str, **_kwargs: Any) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )
    _patch_public_dns(monkeypatch)
    config = create_config(
        {
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com",
        }
    )

    with pytest.raises(ResourceSpaceError) as excinfo:
        _authenticate_live_tenant(
            config,
            "https://curated.resourcespace.example.com",
            "alice@example.com",
            "wrong-password",
            integration=RESOURCE_SPACE_CANVA_INTEGRATION,
        )

    assert excinfo.value.code == "INVALID_CREDENTIALS"
    assert excinfo.value.status_code == 401


def test_live_multipart_upload_uses_resourcespace_canva_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        status_code = 200
        text = '{"uploaded": true}'

        def json(self) -> dict[str, bool]:
            return {"uploaded": True}

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def post(self, url: str, **kwargs: Any) -> FakeResponse:
            captured["url"] = url
            captured["post_kwargs"] = kwargs
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._upload.httpx.Client",
        FakeClient,
    )
    _patch_public_dns(monkeypatch)

    result = _post_multipart_live_api(
        tenant={"apiUrl": "https://assets.example.com/api/"},
        username="alice",
        session_key="session-key",
        params={"function": "upload_multipart", "ref": "123"},
        file_bytes=b"image",
        filename="image.jpg",
        content_type="image/jpeg",
        integration=RESOURCE_SPACE_CANVA_INTEGRATION,
    )

    assert result == {"uploaded": True}
    assert captured["client_kwargs"]["headers"]["User-Agent"] == RESOURCE_SPACE_CANVA_USER_AGENT
    assert "password" not in captured["url"]
    assert captured["post_kwargs"]["files"]["file"] == ("image.jpg", b"image", "image/jpeg")


class _FakeStream:
    def __init__(self, *, status_code: int = 200, headers: dict[str, str] | None = None,
                 chunks: tuple[bytes, ...] = (b"image",)) -> None:
        self.status_code = status_code
        self.headers = headers or {"content-type": "image/jpeg"}
        self._chunks = chunks

    async def __aenter__(self) -> "_FakeStream":
        return self

    async def __aexit__(self, *_args: Any) -> None:
        return None

    async def aiter_bytes(self) -> Any:
        for chunk in self._chunks:
            yield chunk


def _proxy_grant(
    url: str,
    *,
    filename: str = "file.jpg",
    mime_type: str = "image/jpeg",
) -> dict[str, Any]:
    return {
        "ok": True,
        "grant": {
            "source": {"kind": "proxy", "url": url},
            "integration": RESOURCE_SPACE_CANVA_INTEGRATION,
            "mimeType": mime_type,
            "filename": filename,
        },
    }


@pytest.mark.asyncio
async def test_proxy_asset_fetch_uses_resourcespace_canva_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, method: str, url: str, **kwargs: Any) -> _FakeStream:
            captured["method"] = method
            captured["url"] = url
            captured["req_headers"] = kwargs.get("headers")
            captured["extensions"] = kwargs.get("extensions")
            return _FakeStream()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    _patch_public_dns(monkeypatch)
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]

    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/file.jpg"),
    )

    assert response is not None
    assert response[0] == 200
    assert response[1] == b"image"
    assert captured["client_kwargs"]["headers"]["User-Agent"] == RESOURCE_SPACE_CANVA_USER_AGENT
    # Redirects must be disabled explicitly, not left to the httpx default.
    assert captured["client_kwargs"]["follow_redirects"] is False
    # Pinning replaces the request host with a resolved IP; the original host
    # is preserved for the TLS SNI check and the Host header instead.
    assert "93.184.216.34" in captured["url"]
    assert captured["req_headers"]["Host"] == "assets.example.com"
    assert captured["extensions"]["sni_hostname"] == "assets.example.com"


@pytest.mark.asyncio
async def test_proxy_svg_response_is_hardened_for_download(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, method: str, url: str, **kwargs: Any) -> _FakeStream:
            return _FakeStream(
                headers={"content-type": "image/svg+xml"},
                chunks=(b"<svg></svg>",),
            )

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    _patch_public_dns(monkeypatch)
    service = AssetService(config=create_config({"APP_ENV": "development"}), store=None)  # type: ignore[arg-type]

    response = await service.build_grant_response(
        _proxy_grant(
            "https://assets.example.com/evil.svg",
            filename="preview.svg",
            mime_type="image/svg+xml",
        ),
    )

    assert response is not None
    status, _body, headers = response
    assert status == 200
    assert headers["Content-Type"] == "application/octet-stream"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert headers["Content-Disposition"].startswith("attachment;")


@pytest.mark.asyncio
async def test_proxy_asset_fetch_rejects_http_and_never_connects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExplodingAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            raise AssertionError("must not connect to a rejected upstream")

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        ExplodingAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]

    response = await service.build_grant_response(
        _proxy_grant("http://assets.example.com/file.jpg"),
    )
    assert response is None


@pytest.mark.asyncio
async def test_proxy_asset_fetch_rejects_private_upstream_and_never_connects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExplodingAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            raise AssertionError("must not connect to a private upstream")

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        ExplodingAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]

    # 169.254.169.254 (cloud metadata) resolves deterministically as link-local.
    response = await service.build_grant_response(
        _proxy_grant("https://169.254.169.254/latest/meta-data/"),
    )
    assert response is None


@pytest.mark.asyncio
async def test_proxy_asset_fetch_aborts_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, _url: str, **_kwargs: Any) -> _FakeStream:
            # No content-length header, so the cap must trip on the byte stream.
            return _FakeStream(headers={"content-type": "image/jpeg"}, chunks=(b"aaaa", b"bbbb"))

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    _patch_public_dns(monkeypatch)
    service = AssetService(
        config=create_config({"RESOURCE_SPACE_ASSET_PROXY_MAX_BYTES": "5"}),
        store=None,  # type: ignore[arg-type]
    )

    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/big.jpg"),
    )
    # Oversized upstream is aborted without returning partial content.
    assert response is None


@pytest.mark.asyncio
async def test_proxy_asset_fetch_falls_back_to_next_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First validated address is black-holed; the fetch must fall back to the
    # second validated address (under the shared connect deadline).
    def _dual_getaddrinfo(host: str, *_a: Any, **_k: Any) -> list[Any]:
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),  # IPv4, tried first
            (10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),  # IPv6, fallback
        ]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _dual_getaddrinfo,
    )
    attempts: list[str] = []

    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, url: str, **_kwargs: Any) -> _FakeStream:
            attempts.append(url)
            if "93.184.216.34" in url:
                raise httpx.ConnectError("black-holed")
            return _FakeStream()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]

    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/f.jpg"),
    )
    assert response is not None
    assert response[0] == 200
    assert any("93.184.216.34" in u for u in attempts)
    assert any("2606:4700:4700::1111" in u for u in attempts)


@pytest.mark.asyncio
async def test_proxy_asset_fetch_gives_up_on_bad_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A connected-but-bad status must not be retried against other addresses.
    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, _url: str, **_kwargs: Any) -> _FakeStream:
            return _FakeStream(status_code=404)

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    _patch_public_dns(monkeypatch)
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]
    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/missing.jpg"),
    )
    assert response is None


@pytest.mark.asyncio
async def test_proxy_asset_fetch_reads_only_the_winner_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With two connectable addresses, only the winning connection's body is
    # streamed; the loser is closed without its body being read (bounded memory,
    # no N x body buffering).
    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service._PROXY_STAGGER_SECONDS", 0.0
    )

    def _dual_getaddrinfo(host: str, *_a: Any, **_k: Any) -> list[Any]:
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),
            (10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),
        ]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _dual_getaddrinfo,
    )
    body_reads = {"count": 0}

    class TrackingStream(_FakeStream):
        async def aiter_bytes(self) -> Any:
            body_reads["count"] += 1
            for chunk in self._chunks:
                yield chunk

    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, _url: str, **_kwargs: Any) -> "TrackingStream":
            return TrackingStream()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]
    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/f.jpg"),
    )
    assert response is not None
    assert response[0] == 200
    assert body_reads["count"] == 1


@pytest.mark.asyncio
async def test_proxy_race_prefers_acceptable_response_in_same_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # When a bad (404) and a good (200) response complete in the SAME tick, the
    # acceptable one must win deterministically (never a nondeterministic None).
    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service._PROXY_STAGGER_SECONDS", 0.0
    )

    def _dual_getaddrinfo(host: str, *_a: Any, **_k: Any) -> list[Any]:
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),  # index 0 -> bad 404
            (10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),  # index 1 -> good 200
        ]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _dual_getaddrinfo,
    )
    barrier = asyncio.Barrier(2)

    class BarrierStream(_FakeStream):
        async def __aenter__(self) -> "BarrierStream":
            # Both candidates release together, so both land in one done batch.
            await barrier.wait()
            return self

    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, url: str, **_kwargs: Any) -> "BarrierStream":
            status = 404 if "93.184.216.34" in url else 200
            return BarrierStream(status_code=status)

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]
    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/f.jpg"),
    )
    assert response is not None
    assert response[0] == 200


@pytest.mark.asyncio
async def test_proxy_race_retries_after_transport_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A transport error (e.g. ReadTimeout) on the first address is
    # address-specific and must not cancel a healthy second address.
    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service._PROXY_STAGGER_SECONDS", 0.0
    )

    def _dual_getaddrinfo(host: str, *_a: Any, **_k: Any) -> list[Any]:
        return [
            (2, 1, 6, "", ("93.184.216.34", 0)),  # index 0 -> transport error
            (10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),  # index 1 -> healthy 200
        ]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _dual_getaddrinfo,
    )

    class ErrorStream:
        async def __aenter__(self) -> "ErrorStream":
            raise httpx.ReadTimeout("broken first candidate")

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, url: str, **_kwargs: Any) -> Any:
            if "93.184.216.34" in url:
                return ErrorStream()
            return _FakeStream()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]
    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/f.jpg"),
    )
    assert response is not None
    assert response[0] == 200


@pytest.mark.asyncio
async def test_proxy_race_propagates_unexpected_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A non-transport (programming/config) error must surface, not be silently
    # converted to a missing asset.
    _patch_public_dns(monkeypatch)

    class BoomStream:
        async def __aenter__(self) -> "BoomStream":
            raise ValueError("unexpected bug")

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, _url: str, **_kwargs: Any) -> "BoomStream":
            return BoomStream()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        await service.build_grant_response(
            _proxy_grant("https://assets.example.com/f.jpg"),
        )


@pytest.mark.asyncio
async def test_proxy_race_propagates_raw_timeout_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A built-in TimeoutError from a candidate is NOT the connect deadline and
    # must propagate, not be swallowed by the deadline handler (and returned as
    # a missing asset).
    _patch_public_dns(monkeypatch)

    class TimeoutStream:
        async def __aenter__(self) -> "TimeoutStream":
            raise TimeoutError("not the asyncio deadline")

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, _url: str, **_kwargs: Any) -> "TimeoutStream":
            return TimeoutStream()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]
    with pytest.raises(TimeoutError):
        await service.build_grant_response(
            _proxy_grant("https://assets.example.com/f.jpg"),
        )


@pytest.mark.asyncio
async def test_proxy_race_deadline_expiry_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A genuine connect-deadline expiry is NOT an error: it yields None (a
    # missing asset), distinct from a candidate raising a raw TimeoutError.
    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service._PROXY_CONNECT_DEADLINE_SECONDS", 0.05
    )
    _patch_public_dns(monkeypatch)

    class HangStream:
        async def __aenter__(self) -> "HangStream":
            await asyncio.sleep(10)  # never completes before the deadline
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

    class FakeAsyncClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        def stream(self, _method: str, _url: str, **_kwargs: Any) -> "HangStream":
            return HangStream()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]
    response = await service.build_grant_response(
        _proxy_grant("https://assets.example.com/f.jpg"),
    )
    assert response is None


# --- SSO session-key validation (live path) ---------------------------------

_SSO_TENANT = {
    "id": "tenant_curated",
    "slug": "curated",
    "name": "Curated",
    "baseUrl": "https://curated.resourcespace.example.com",
    "apiUrl": "https://api.curated.resourcespace.example.com/",
}


def _patch_live_get(monkeypatch: pytest.MonkeyPatch, *, json_value: Any, raise_json: bool, text: str,
                    status_code: int = 200) -> dict[str, Any]:
    """Patch the live backend's httpx.Client so a signed GET returns a canned
    body. Returns a dict that captures the requested URL."""
    captured: dict[str, Any] = {}

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = status_code
            self.text = text

        def json(self) -> Any:
            if raise_json:
                raise ValueError("not json")
            return json_value

    class FakeClient:
        def __init__(self, **_kwargs: Any) -> None:
            return None

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *_args: Any) -> None:
            return None

        def get(self, url: str, **kwargs: Any) -> FakeResponse:
            captured["url"] = url
            captured["req_headers"] = kwargs.get("headers")
            captured["extensions"] = kwargs.get("extensions")
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )
    return captured


def _live_sso_service() -> Any:
    config = create_config(
        {"RESOURCE_SPACE_MODE": "live", "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com"}
    )
    return create_resourcespace_service(config)


def test_authenticate_with_session_key_live_accepts_json_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # HTTP 200 + an (empty) JSON list is a valid restricted user.
    _patch_public_dns(monkeypatch)
    captured = _patch_live_get(monkeypatch, json_value=[], raise_json=False, text="[]")
    session = _live_sso_service().authenticate_with_session_key(
        tenant=_SSO_TENANT,
        session_key="rs-session-key",
        username="alice@example.com",
    )
    assert session["upstream"]["mode"] == "live"
    assert session["upstream"]["sessionKey"] == "rs-session-key"
    assert session["user"]["username"] == "alice@example.com"
    assert session["user"]["id"] == "tenant_curated:alice@example.com"
    assert session["user"]["displayName"] == "alice@example.com"
    assert "email" not in session["user"]
    # The signed call carries the exact-case username and never the raw key.
    assert "user=alice%40example.com" in captured["url"]
    assert "function=get_resource_types" in captured["url"]
    assert "rs-session-key" not in captured["url"]


def test_authenticate_with_session_key_preserves_username_casing_for_signing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_public_dns(monkeypatch)
    captured = _patch_live_get(monkeypatch, json_value=[], raise_json=False, text="[]")
    session = _live_sso_service().authenticate_with_session_key(
        tenant=_SSO_TENANT,
        session_key="rs-session-key",
        username="Alice",
    )
    assert session["user"]["username"] == "Alice"
    assert session["user"]["id"] == "tenant_curated:alice"
    assert "user=Alice" in captured["url"]
    assert "function=get_resource_types" in captured["url"]


@pytest.mark.parametrize(
    "json_value,raise_json,text",
    [
        (False, False, "false"),
        ("false", False, '"false"'),
        ("", False, '""'),
        (None, False, "null"),
        ({"error": True}, False, '{"error": true}'),
        (None, True, "<html>error</html>"),
    ],
)
def test_authenticate_with_session_key_live_rejects_2xx_non_list_body(
    monkeypatch: pytest.MonkeyPatch, json_value: Any, raise_json: bool, text: str
) -> None:
    # ResourceSpace signals auth failure with HTTP 200 + a falsy/non-list body
    # as often as with 401/403. Any non-list body must fail validation so no
    # broker authorization code can be minted for an invalid session key.
    _patch_public_dns(monkeypatch)
    _patch_live_get(monkeypatch, json_value=json_value, raise_json=raise_json, text=text)
    with pytest.raises(ResourceSpaceError) as excinfo:
        _live_sso_service().authenticate_with_session_key(
            tenant=_SSO_TENANT,
            session_key="rs-session-key",
            username="alice@example.com",
        )
    assert excinfo.value.code == "UPSTREAM_SESSION_EXPIRED"


def test_authenticate_with_session_key_rejects_missing_username_before_upstream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExplodingClient:
        def __init__(self, **_kwargs: Any) -> None:
            raise AssertionError("must not call upstream without a username")

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        ExplodingClient,
    )
    with pytest.raises(ResourceSpaceError) as excinfo:
            _live_sso_service().authenticate_with_session_key(
                tenant=_SSO_TENANT,
                session_key="rs-session-key",
                username="   ",
            )
    assert excinfo.value.code == "SSO_HANDOFF_FAILED"


# --- Private-IP / SSRF classification ---------------------------------------


def test_is_private_ip_rejects_cgnat_and_special_ranges() -> None:
    # Literal IPs resolve deterministically. CGNAT/shared space (100.64.0.0/10)
    # is neither is_private nor is_reserved in 3.11, so the is_global backstop
    # must catch it.
    for host in ("100.64.0.1", "192.0.0.1", "198.18.0.1", "0.0.0.0", "10.0.0.1", "127.0.0.1"):
        assert _is_private_ip(host) is True, host
    # IPv6 site-local (fec0::/10) reports is_global=True under Python 3.11, so it
    # must be caught explicitly by the is_site_local check.
    for host in ("fec0::1", "fc00::1", "fe80::1", "::1"):
        assert _is_private_ip(host) is True, host
    # Genuine public addresses are allowed.
    for host in ("93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"):
        assert _is_private_ip(host) is False, host


def test_pin_request_pins_to_resolved_ip_and_preserves_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_public_dns(monkeypatch)
    pinned_urls, headers, extensions = pin_request(
        "https://api.tenant.example.com/api/?user=alice&function=get_user_collections&sign=abc"
    )
    # Host is replaced with the validated IP so httpx connects there without
    # re-resolving; the query is untouched.
    assert pinned_urls[0].startswith("https://93.184.216.34/api/")
    assert "user=alice" in pinned_urls[0] and "sign=abc" in pinned_urls[0]
    assert "tenant.example.com" not in pinned_urls[0]
    # The original host is preserved for the TLS SNI/cert check and Host header.
    assert headers["Host"] == "api.tenant.example.com"
    assert extensions["sni_hostname"] == "api.tenant.example.com"


def test_pin_request_rejects_private_and_non_https() -> None:
    # Literal private/internal addresses are rejected outright (no rebind window).
    for url in (
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/api/",
        "https://[fec0::1]/api/",
    ):
        with pytest.raises(ResourceSpaceError) as excinfo:
            pin_request(url)
        assert excinfo.value.code == "FORBIDDEN", url
    # Non-https is refused.
    with pytest.raises(ResourceSpaceError):
        pin_request("http://api.tenant.example.com/api/")


def test_resolve_pinned_addresses_orders_ipv4_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A host that resolves IPv6-first must still expose the IPv4 address so the
    # caller can fall back (Railway disables outbound IPv6 by default).
    def _fake_getaddrinfo(host: str, *_a: Any, **_k: Any) -> list[Any]:
        return [
            (10, 1, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),  # IPv6 first
            (2, 1, 6, "", ("93.184.216.34", 0)),  # IPv4 second
        ]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _fake_getaddrinfo,
    )
    addresses = resolve_pinned_addresses("dual.example.com")
    assert addresses == ["93.184.216.34", "2606:4700:4700::1111"]
    pinned_urls, _headers, _ext = pin_request("https://dual.example.com/api/")
    # One candidate per address, IPv4 first, IPv6 bracketed.
    assert pinned_urls[0].startswith("https://93.184.216.34/")
    assert pinned_urls[1].startswith("https://[2606:4700:4700::1111]/")


def test_pin_request_brackets_ipv6_authority() -> None:
    # A public IPv6 literal authority must be bracketed in the Host header.
    pinned_urls, headers, extensions = pin_request("https://[2606:4700:4700::1111]/api/")
    assert headers["Host"] == "[2606:4700:4700::1111]"
    assert extensions["sni_hostname"] == "2606:4700:4700::1111"
    assert pinned_urls[0].startswith("https://[2606:4700:4700::1111]/")


def test_pin_request_idna_uses_uts46_resolver_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The stdlib IDNA 2003 codec maps faß.de -> fass.de, a DIFFERENT domain that
    # resolves to different IPs. pin_request must canonicalise via httpx UTS46 to
    # xn--fa-hia.de and resolve THAT exact host, so credentials/session keys can
    # never be sent to the wrong domain.
    resolved_hosts: list[str] = []

    def _recording_getaddrinfo(host: str, *_a: Any, **_k: Any) -> list[Any]:
        resolved_hosts.append(host)
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _recording_getaddrinfo,
    )
    pinned_urls, headers, extensions = pin_request("https://faß.de/api/")
    # The resolver was asked for the UTS46 host, not the IDNA-2003 "fass.de".
    assert resolved_hosts == ["xn--fa-hia.de"]
    assert "fass.de" not in resolved_hosts
    assert headers["Host"] == "xn--fa-hia.de"
    assert extensions["sni_hostname"] == "xn--fa-hia.de"
    assert pinned_urls[0].startswith("https://93.184.216.34/")


def test_resolve_pinned_ip_returns_public_literal() -> None:
    assert resolve_pinned_ip("93.184.216.34") == "93.184.216.34"
    with pytest.raises(ResourceSpaceError):
        resolve_pinned_ip("10.0.0.1")


def test_host_matches_strict_bare_entry_is_exact_only() -> None:
    # A bare entry authorises only the exact host, not its subdomains.
    assert _host_matches_strict("cdn.example.com", "cdn.example.com") is True
    assert _host_matches_strict("attacker.cdn.example.com", "cdn.example.com") is False
    # A leading-dot entry authorises the domain and its subdomains.
    assert _host_matches_strict("example.com", ".example.com") is True
    assert _host_matches_strict("sub.example.com", ".example.com") is True
    assert _host_matches_strict("notexample.com", ".example.com") is False


def test_validate_export_url_dot_suffix_allows_apex_and_subdomains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._upload._is_private_ip",
        lambda _host: False,
    )
    config = create_config({"CANVA_UPLOAD_ALLOWED_HOSTS": ".example.com"})
    _validate_export_url("https://example.com/export.png", config)
    _validate_export_url("https://sub.example.com/export.png", config)
    with pytest.raises(ResourceSpaceError):
        _validate_export_url("https://notexample.com/export.png", config)


def test_validate_export_url_bare_host_is_exact_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._upload._is_private_ip",
        lambda _host: False,
    )
    config = create_config({"CANVA_UPLOAD_ALLOWED_HOSTS": "cdn.example.com"})
    _validate_export_url("https://cdn.example.com/export.png", config)
    with pytest.raises(ResourceSpaceError):
        _validate_export_url("https://attacker.cdn.example.com/export.png", config)


def test_pin_request_allowlist_rejects_non_allowlisted_subdomain() -> None:
    # Allowlist rejection happens on the canonical host before any DNS lookup.
    with pytest.raises(ResourceSpaceError) as excinfo:
        pin_request(
            "https://attacker.cdn.example.com/x.jpg", allowed_hosts=["cdn.example.com"]
        )
    assert excinfo.value.code == "FORBIDDEN"


def test_canonical_ascii_host_uses_uts46_not_idna2003() -> None:
    # The credential-target bug: stdlib IDNA 2003 maps faß.de -> fass.de.
    assert canonical_ascii_host("faß.de") == "xn--fa-hia.de"
    assert canonical_ascii_host("API.Example.COM") == "api.example.com"
    assert canonical_ascii_host("93.184.216.34") == "93.184.216.34"


def test_unicode_host_canonicalised_before_resolution_on_all_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every validating path (tenant private-IP guard, asset pin, export fetch)
    # must resolve the UTS46 host xn--fa-hia.de, never the stdlib IDNA-2003
    # sibling fass.de (a different domain that could be private/attacker-owned).
    recorded: list[str] = []

    def _recording_getaddrinfo(host: str, *_a: Any, **_k: Any) -> list[Any]:
        recorded.append(host)
        return [(2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._helpers.socket.getaddrinfo",
        _recording_getaddrinfo,
    )

    # Tenant path (live-mode private-IP guard on a Unicode tenant URL).
    tenant_config = create_config(
        {"RESOURCE_SPACE_MODE": "live", "RESOURCE_SPACE_ALLOWED_HOSTS": ".de"}
    )
    get_configured_tenant(tenant_config, "https://faß.de")
    # Asset path.
    pin_request("https://faß.de/thumb.jpg", allowed_hosts=[".de"])
    # Export path.
    _validate_export_url("https://faß.de/export.png", create_config({}))

    assert recorded, "expected the resolver to be exercised"
    assert set(recorded) == {"xn--fa-hia.de"}, recorded
    assert "fass.de" not in recorded


def test_host_matchers_canonicalise_unicode_patterns() -> None:
    # A canonical host must match a configured Unicode pattern (both -> UTS46).
    # An ASCII pattern like ".de" cannot surface this; a Unicode pattern can.
    assert _host_matches_strict("xn--fa-hia.de", "faß.de") is True
    assert _host_matches_strict("sub.xn--fa-hia.de", ".faß.de") is True
    assert _host_matches_strict("xn--fa-hia.de", "other.de") is False
    assert _host_matches_pattern("xn--fa-hia.de", "faß.de") is True
    assert _host_matches_pattern("sub.xn--fa-hia.de", ".faß.de") is True


def test_unicode_allowlist_pattern_matches_unicode_host_across_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_public_dns(monkeypatch)
    # Asset: a Unicode allowlist pattern must accept the matching Unicode host.
    pin_request("https://faß.de/thumb.jpg", allowed_hosts=["faß.de"])
    pin_request("https://sub.faß.de/thumb.jpg", allowed_hosts=[".faß.de"])
    # Tenant: live-mode allowlist with a Unicode pattern accepts the tenant.
    tenant_config = create_config(
        {"RESOURCE_SPACE_MODE": "live", "RESOURCE_SPACE_ALLOWED_HOSTS": "faß.de"}
    )
    tenant = get_configured_tenant(tenant_config, "https://faß.de")
    assert tenant["baseUrl"] == "https://xn--fa-hia.de"
    # Export: a Unicode CANVA_UPLOAD_ALLOWED_HOSTS pattern accepts the host.
    export_config = create_config({"CANVA_UPLOAD_ALLOWED_HOSTS": "faß.de"})
    _validate_export_url("https://faß.de/export.png", export_config)  # must not raise
    # A non-matching host is still rejected.
    with pytest.raises(ResourceSpaceError):
        pin_request("https://faß.de/x", allowed_hosts=["other.de"])


def test_get_configured_tenant_matches_unicode_record_via_punycode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A configured Unicode tenant must be found when requested via its punycode
    # form (and vice versa), keeping its apiUrl override and collection scoping
    # rather than degrading to a generic ad-hoc tenant.
    _patch_public_dns(monkeypatch)
    config = create_config(
        {
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".de",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [
                    {
                        "id": "tenant_uni",
                        "slug": "uni",
                        "name": "Unicode",
                        "baseUrl": "https://faß.de",
                        "apiUrl": "https://api.faß.de/",
                        "rootCollections": [5],
                    }
                ]
            ),
        }
    )
    tenant = get_configured_tenant(config, "https://xn--fa-hia.de")
    assert tenant["id"] == "tenant_uni"
    assert tenant["apiUrl"] == "https://api.faß.de/"
    assert tenant["rootCollections"] == [5]

    # Inverse: record stored in punycode, requested in Unicode.
    config2 = create_config(
        {
            "RESOURCE_SPACE_MODE": "live",
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".de",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [
                    {
                        "id": "tenant_puny",
                        "slug": "puny",
                        "name": "Puny",
                        "baseUrl": "https://xn--fa-hia.de",
                        "rootCollections": [7],
                    }
                ]
            ),
        }
    )
    tenant2 = get_configured_tenant(config2, "https://faß.de")
    assert tenant2["id"] == "tenant_puny"
    assert tenant2["rootCollections"] == [7]


def test_tenant_identity_is_structured_and_unambiguous() -> None:
    # IPv6 bracket ambiguity: [2606:4700::1111]:443 (host + port 443) must NOT
    # collide with the distinct host [2606:4700::1111:443].
    with_port = _tenant_identity("https://[2606:4700::1111]:443/")
    longer_host = _tenant_identity("https://[2606:4700::1111:443]/")
    assert with_port is not None and longer_host is not None
    assert with_port != longer_host
    # Default port equals an explicit 443.
    assert _tenant_identity("https://[2606:4700::1111]/") == with_port
    assert _tenant_identity("https://host.example.com/") == _tenant_identity(
        "https://host.example.com:443/"
    )
    # Compressed and expanded IPv6 forms are equivalent.
    assert _tenant_identity("https://[2606:4700:0:0:0:0:0:1111]/") == _tenant_identity(
        "https://[2606:4700::1111]/"
    )
    # Unicode and punycode forms are equivalent.
    assert _tenant_identity("https://faß.de/") == _tenant_identity("https://xn--fa-hia.de/")
    # An explicit :0 is preserved and is NOT equal to the scheme default.
    assert _tenant_identity("https://h.example:0/") != _tenant_identity("https://h.example/")
    assert _tenant_identity("https://h.example:0/") != _tenant_identity("https://h.example:443/")


# --- Mode normalisation + non-fixture guard ---------------------------------


def test_mode_is_normalised_case_and_whitespace() -> None:
    assert create_config({"RESOURCE_SPACE_MODE": "Live "}).resource_space.mode == "live"
    assert create_config({"RESOURCE_SPACE_MODE": " FIXTURE"}).resource_space.mode == "fixture"


def test_get_configured_tenant_guards_unknown_non_fixture_mode() -> None:
    # Any value that is not exactly "fixture" dispatches to the live backend, so
    # the SSRF guard must run for it too (not only the literal "live").
    for mode in ("live", "Live", "staging", "prod"):
        config = create_config({"RESOURCE_SPACE_MODE": mode})
        with pytest.raises(ResourceSpaceError) as excinfo:
            get_configured_tenant(config, "https://169.254.169.254")
        assert excinfo.value.code == "FORBIDDEN", mode
