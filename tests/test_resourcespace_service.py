"""ResourceSpace service helper tests.

Mirrors the Node `resourcespace-service.test.js` suite.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from resourcespace_platform.config import create_config
from resourcespace_platform.services.asset_service import AssetService
from resourcespace_platform.services.resourcespace import (
    ResourceSpaceError,
    build_live_asset,
    build_live_search_string,
    get_configured_tenant,
    normalize_live_asset_page,
)
from resourcespace_platform.services.resourcespace._helpers import (
    RESOURCE_SPACE_CANVA_INTEGRATION,
    RESOURCE_SPACE_CANVA_USER_AGENT,
)
from resourcespace_platform.services.resourcespace._live_backend import (
    _authenticate_live_tenant,
    _fetch_jsonish_sync,
)
from resourcespace_platform.services.resourcespace._upload import _post_multipart_live_api


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

        def get(self, url: str) -> FakeResponse:
            captured["url"] = url
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )

    assert _fetch_jsonish_sync(
        "https://assets.example.com/api/?function=get_user_collections",
        integration=RESOURCE_SPACE_CANVA_INTEGRATION,
    ) == {"ok": True}
    assert captured["client_kwargs"]["headers"]["User-Agent"] == RESOURCE_SPACE_CANVA_USER_AGENT


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

        def get(self, _url: str) -> FakeResponse:
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.resourcespace._live_backend.httpx.Client",
        FakeClient,
    )

    assert _fetch_jsonish_sync(
        "https://assets.example.com/api/?function=get_user_collections",
        integration="tagquest",
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

    assert captured["url"] == "https://api.curated.resourcespace.example.com/"
    assert "secret-password" not in captured["url"]
    assert "alice%40example.com" not in captured["url"]
    assert captured["post_kwargs"]["data"] == {
        "function": "login",
        "username": "alice@example.com",
        "password": "secret-password",
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
        integration="tagquest",
    )

    assert captured["url"] == "https://api.curated.resourcespace.example.com/"
    assert "secret-password" not in captured["url"]
    assert captured["post_kwargs"]["data"]["password"] == "secret-password"
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


@pytest.mark.asyncio
async def test_proxy_asset_fetch_uses_resourcespace_canva_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        status_code = 200
        content = b"image"
        headers = {"content-type": "image/jpeg"}

    class FakeAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        async def __aenter__(self) -> "FakeAsyncClient":
            return self

        async def __aexit__(self, *_args: Any) -> None:
            return None

        async def get(self, url: str) -> FakeResponse:
            captured["url"] = url
            return FakeResponse()

    monkeypatch.setattr(
        "resourcespace_platform.services.asset_service.httpx.AsyncClient",
        FakeAsyncClient,
    )
    service = AssetService(config=create_config(), store=None)  # type: ignore[arg-type]

    response = await service.build_grant_response(
        {
            "ok": True,
            "grant": {
                "source": {"kind": "proxy", "url": "https://assets.example.com/file.jpg"},
                "integration": RESOURCE_SPACE_CANVA_INTEGRATION,
                "mimeType": "image/jpeg",
                "filename": "file.jpg",
            },
        },
    )

    assert response is not None
    assert response[0] == 200
    assert captured["client_kwargs"]["headers"]["User-Agent"] == RESOURCE_SPACE_CANVA_USER_AGENT
    assert captured["url"] == "https://assets.example.com/file.jpg"
