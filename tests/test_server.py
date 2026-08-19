"""Full-stack integration tests against the Python broker.

Mirrors the Node `server.test.js` suite. Uses FastAPI's httpx TestClient; no
real sockets needed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from resourcespace_platform.config import create_config
from resourcespace_platform.http_utils import decode_continuation
from resourcespace_platform.main import create_app
from resourcespace_platform.routes.content import _advance_asset_offset


def _pkce_pair() -> tuple[str, str]:
    verifier = "verifier-value-123456789"
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _build_client(**overrides: str) -> Iterator[tuple[TestClient, str]]:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)

    env: dict[str, str] = {
        "APP_ENV": "development",
        "PORT": "0",
        "BASE_URL": "http://testserver",
        "OAUTH_ISSUER": "http://testserver",
        "OAUTH_CLIENT_ID": "canva-dev-app",
        "ASSET_SIGNING_SECRET": "test-signing-secret",
        "STORAGE_PATH": storage_path,
        "RESOURCE_SPACE_MODE": "fixture",
        "CANVA_REQUEST_VERIFICATION_MODE": "smart",
    }
    env.update(overrides)
    config = create_config(env)
    app = create_app(config)
    client = TestClient(app, base_url="http://testserver")
    try:
        yield client, storage_path
    finally:
        client.close()
        if os.path.exists(storage_path):
            os.remove(storage_path)


@pytest.fixture
def harness() -> Iterator[tuple[TestClient, str]]:
    yield from _build_client()


def _authorize_as(
    client: TestClient,
    *,
    tenant_url: str,
    username: str,
    password: str,
) -> dict[str, Any]:
    verifier, challenge = _pkce_pair()
    redirect_uri = "https://example.com/oauth/callback"

    response = client.post(
        "/oauth/authorise",
        data={
            "client_id": "canva-dev-app",
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": "state-123",
            "scope": "openid dam:read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "tenant_url": tenant_url,
            "username": username,
            "password": password,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    location = response.headers["location"]
    callback = urlparse(location)
    code = parse_qs(callback.query)["code"][0]

    token_response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "canva-dev-app",
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": verifier,
        },
    )
    assert token_response.status_code == 200, token_response.text
    return token_response.json()


def _find_resources(client: TestClient, access_token: str, body: dict[str, Any]) -> dict[str, Any]:
    response = client.post(
        "/content/resources/find",
        headers={"Authorization": f"Bearer {access_token}"},
        json=body,
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_oauth_login_yields_token_and_session(harness: tuple[TestClient, str]) -> None:
    client, storage_path = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    assert tokens["access_token"]
    assert tokens["refresh_token"]

    me = client.get(
        "/api/session",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert me.status_code == 200
    payload = me.json()
    assert payload["user"]["username"] == "alice"
    assert payload["tenant"]["id"] == "tenant_acme"

    state = json.loads(Path(storage_path).read_text())
    record = state["accessTokens"][tokens["access_token"]]
    assert record["integration"] == "canva"
    assert record["session"]["broker"] == {
        "clientId": "canva-dev-app",
        "integration": "canva",
    }


def test_root_returns_service_summary(harness: tuple[TestClient, str]) -> None:
    client, _ = harness
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["service"] == "ResourceSpace Canva Platform Broker"
    assert payload["ok"] is True
    assert payload["endpoints"]["healthz"] == "/healthz"
    assert payload["endpoints"]["authorise"] == "/oauth/authorise"


def test_authorize_page_supports_manual_fixture_flow(harness: tuple[TestClient, str]) -> None:
    client, _ = harness
    redirect = client.get("/oauth/authorize", follow_redirects=False)
    assert redirect.status_code == 307
    assert redirect.headers["location"] == "/oauth/authorise"

    response = client.get("/oauth/authorise")
    assert response.status_code == 200
    assert "Manual test mode is active" in response.text

    authorize = client.post(
        "/oauth/authorise",
        data={
            "tenant_url": "https://acme.demo.resourcespace.local",
            "username": "alice",
            "password": "alice-password",
        },
        follow_redirects=False,
    )
    assert authorize.status_code == 302
    location = urlparse(authorize.headers["location"])
    assert location.path == "/oauth/manual/callback"

    callback = client.get(f"{location.path}?{location.query}")
    assert callback.status_code == 200
    payload = callback.json()
    assert payload["type"] == "SUCCESS"
    assert payload["session"]["user"]["username"] == "alice"
    assert payload["session"]["tenant"]["id"] == "tenant_acme"


def test_root_resource_discovery_returns_containers_and_images(
    harness: tuple[TestClient, str],
) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    payload = _find_resources(
        client,
        tokens["access_token"],
        {"limit": 10, "locale": "en-GB", "types": ["CONTAINER", "IMAGE"]},
    )
    assert payload["type"] == "SUCCESS"
    assert any(resource["type"] == "CONTAINER" for resource in payload["resources"])
    assert any(resource["type"] == "IMAGE" for resource in payload["resources"])


def test_tenant_isolation_hides_other_tenant_assets(
    harness: tuple[TestClient, str],
) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="bob",
        password="bob-password",
    )
    payload = _find_resources(
        client,
        tokens["access_token"],
        {"limit": 10, "locale": "en-GB", "types": ["IMAGE"], "query": "Globex"},
    )
    assert payload["type"] == "SUCCESS"
    assert payload["resources"] == []


def test_restricted_user_cannot_see_private_asset(
    harness: tuple[TestClient, str],
) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="bob",
        password="bob-password",
    )
    payload = _find_resources(
        client,
        tokens["access_token"],
        {"limit": 10, "locale": "en-GB", "types": ["IMAGE"], "query": "Confidential"},
    )
    assert payload["type"] == "SUCCESS"
    assert payload["resources"] == []


def test_unsupported_asset_cannot_mint_download_grant(
    harness: tuple[TestClient, str],
) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    response = client.post(
        "/content/resources/asset_board_minutes/download-url",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 409
    payload = response.json()
    assert payload["error"]["code"] == "UNSUPPORTED_FORMAT"


def test_signed_asset_url_expires_cleanly(harness: tuple[TestClient, str]) -> None:
    client, _ = harness
    response = client.get(
        "/signed/assets/grant_test",
        params={"expires": "0", "sig": "invalid"},
    )
    assert response.status_code == 410


def test_canva_uninstall_revokes_session() -> None:
    for client, _ in _build_client(CANVA_REQUEST_VERIFICATION_MODE="off"):
        tokens = _authorize_as(
            client,
            tenant_url="https://acme.demo.resourcespace.local",
            username="alice",
            password="alice-password",
        )

        uninstall = client.post(
            "/webhooks/canva/user-uninstall",
            json={"user_id": "user_alice", "tenant_id": "tenant_acme"},
        )
        assert uninstall.status_code == 200

        session = client.get(
            "/api/session",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert session.status_code == 401
        assert session.json()["error"]["code"] == "SESSION_EXPIRED"


def test_advance_asset_offset_uses_scanned_rows() -> None:
    assert _advance_asset_offset(0, {"items": [], "scanned": 20}, 20) == 20
    assert _advance_asset_offset(0, {"items": [{"id": "1"}], "scanned": 50}, 100) == 50
    assert _advance_asset_offset(0, {"items": []}, 20) == 20
    assert _advance_asset_offset(10, {"items": [{"id": "1"}, {"id": "2"}]}, 40) == 12


def test_find_does_not_loop_when_filtered_page_consumes_all_rows(
    harness: tuple[TestClient, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    monkeypatch.setattr(
        client.app.state.deps.resourcespace_service,
        "list_assets",
        lambda *args, **kwargs: {"items": [], "total": 20, "scanned": 20},
    )
    payload = _find_resources(
        client,
        tokens["access_token"],
        {"limit": 50, "locale": "en-GB", "types": ["IMAGE"]},
    )
    assert payload["type"] == "SUCCESS"
    assert payload["resources"] == []
    assert "continuation" not in payload


def test_find_continues_from_scanned_offset_not_kept_items(
    harness: tuple[TestClient, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    monkeypatch.setattr(
        client.app.state.deps.resourcespace_service,
        "list_assets",
        lambda *args, **kwargs: {
            "items": [
                {
                    "id": "101",
                    "name": "Keep Me",
                    "mimeType": "image/jpeg",
                    "filename": "keep.jpg",
                    "thumbnailSource": {
                        "kind": "proxy",
                        "url": "https://assets.example.com/101-thm.jpg",
                        "mimeType": "image/jpeg",
                        "width": 100,
                        "height": 80,
                    },
                    "previewSource": {
                        "kind": "proxy",
                        "url": "https://assets.example.com/101-pre.jpg",
                        "mimeType": "image/jpeg",
                        "width": 100,
                        "height": 80,
                    },
                }
            ],
            "total": 100,
            "scanned": 50,
        },
    )
    payload = _find_resources(
        client,
        tokens["access_token"],
        {"limit": 50, "locale": "en-GB", "types": ["IMAGE"]},
    )
    assert payload["type"] == "SUCCESS"
    assert [resource["id"] for resource in payload["resources"]] == ["101"]
    continuation = decode_continuation(payload["continuation"])
    assert continuation is not None
    assert continuation["assetOffset"] == 50
