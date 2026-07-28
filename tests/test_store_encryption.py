"""Tests for encrypted store persistence and proactive retention pruning."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from resourcespace_platform.config import create_config
from resourcespace_platform.dependencies import build_dependencies
from resourcespace_platform.main import create_app
from resourcespace_platform.services.field_crypto import ENC_PREFIX
from resourcespace_platform.services.json_store import JsonStoreLoadError

ACME_TENANT_URL = "https://acme.demo.resourcespace.local"
REDIRECT_URI = "https://example.com/oauth/callback"


def _pkce_pair() -> tuple[str, str]:
    verifier = "verifier-value-123456789"
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _live_session(*, session_key: str = "rs-secret-session-key") -> dict[str, Any]:
    return {
        "tenant": {
            "id": "tenant_acme",
            "slug": "acme",
            "name": "Acme",
            "baseUrl": ACME_TENANT_URL,
        },
        "user": {
            "id": "tenant_acme:alice",
            "username": "alice",
            "displayName": "alice",
            "role": "member",
        },
        "upstream": {
            "mode": "live",
            "sessionKey": session_key,
            "authenticatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }


def test_encrypted_store_hides_session_key_and_wrong_key_returns_401() -> None:
    key_a = Fernet.generate_key().decode()
    key_b = Fernet.generate_key().decode()
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    session_key = "rs-secret-session-key"
    tokens: dict[str, Any] = {}

    config_a = create_config(
        {
            "APP_ENV": "development",
            "PORT": "0",
            "BASE_URL": "http://testserver",
            "OAUTH_ISSUER": "http://testserver",
            "OAUTH_CLIENT_ID": "canva-dev-app",
            "ASSET_SIGNING_SECRET": "test-signing-secret",
            "STORAGE_PATH": storage_path,
            "RESOURCE_SPACE_MODE": "fixture",
            "STORAGE_ENCRYPTION_KEY": key_a,
        }
    )
    deps = build_dependencies(config_a)
    verifier, challenge = _pkce_pair()
    code = deps.auth_service.begin_authorization_from_session(
        client_id="canva-dev-app",
        redirect_uri=REDIRECT_URI,
        scope="openid dam:read",
        code_challenge=challenge,
        code_challenge_method="S256",
        session=_live_session(session_key=session_key),
    )
    raw_store = Path(storage_path).read_text()
    assert ENC_PREFIX in raw_store
    assert session_key not in raw_store

    client = TestClient(create_app(config_a), base_url="http://testserver")
    try:
        tokens = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "canva-dev-app",
                "redirect_uri": REDIRECT_URI,
                "code": code,
                "code_verifier": verifier,
            },
        ).json()
        userinfo = client.get(
            "/oauth/userinfo",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        assert userinfo.status_code == 200
    finally:
        client.close()

    config_b = create_config(
        {
            "APP_ENV": "development",
            "PORT": "0",
            "BASE_URL": "http://testserver",
            "OAUTH_ISSUER": "http://testserver",
            "OAUTH_CLIENT_ID": "canva-dev-app",
            "ASSET_SIGNING_SECRET": "test-signing-secret",
            "STORAGE_PATH": storage_path,
            "RESOURCE_SPACE_MODE": "fixture",
            "STORAGE_ENCRYPTION_KEY": key_b,
        }
    )
    with TestClient(create_app(config_b), base_url="http://testserver") as rotated_client:
        userinfo = rotated_client.get(
            "/oauth/userinfo",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        assert userinfo.status_code == 401
        refresh = rotated_client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "canva-dev-app",
                "refresh_token": tokens["refresh_token"],
            },
        )
        assert refresh.status_code == 400
        assert refresh.json()["error"] == "invalid_grant"

    if os.path.exists(storage_path):
        os.remove(storage_path)


def test_dev_fallback_without_encryption_key_still_works() -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    config = create_config(
        {
            "APP_ENV": "development",
            "PORT": "0",
            "BASE_URL": "http://testserver",
            "OAUTH_ISSUER": "http://testserver",
            "OAUTH_CLIENT_ID": "canva-dev-app",
            "ASSET_SIGNING_SECRET": "test-signing-secret",
            "STORAGE_PATH": storage_path,
            "RESOURCE_SPACE_MODE": "fixture",
        }
    )
    deps = build_dependencies(config)
    verifier, challenge = _pkce_pair()
    code = deps.auth_service.begin_authorization_from_session(
        client_id="canva-dev-app",
        redirect_uri=REDIRECT_URI,
        scope="openid dam:read",
        code_challenge=challenge,
        code_challenge_method="S256",
        session=_live_session(),
    )
    assert ENC_PREFIX not in Path(storage_path).read_text()

    with TestClient(create_app(config), base_url="http://testserver") as client:
        tokens = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "canva-dev-app",
                "redirect_uri": REDIRECT_URI,
                "code": code,
                "code_verifier": verifier,
            },
        ).json()
        userinfo = client.get(
            "/oauth/userinfo",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        assert userinfo.status_code == 200

    if os.path.exists(storage_path):
        os.remove(storage_path)


def test_lifespan_prune_removes_expired_records() -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    expired_token = "at_expired_prune_test"
    store = {
        "authorizationCodes": {},
        "accessTokens": {
            expired_token: {
                "accessToken": expired_token,
                "clientId": "canva-dev-app",
                "scope": "openid",
                "integration": "canva",
                "session": {
                    "tenant": {"id": "tenant_acme", "slug": "acme", "name": "Acme"},
                    "user": {"id": "user_alice", "username": "alice", "displayName": "Alice", "role": "admin"},
                    "upstream": {"mode": "fixture"},
                    "broker": {"clientId": "canva-dev-app", "integration": "canva"},
                },
                "expiresAt": 1,
                "createdAt": 1,
            }
        },
        "refreshTokens": {},
        "assetGrants": {},
        "pendingSsoStates": {},
    }
    Path(storage_path).write_text(json.dumps(store))

    config = create_config(
        {
            "APP_ENV": "development",
            "PORT": "0",
            "BASE_URL": "http://testserver",
            "OAUTH_ISSUER": "http://testserver",
            "OAUTH_CLIENT_ID": "canva-dev-app",
            "ASSET_SIGNING_SECRET": "test-signing-secret",
            "STORAGE_PATH": storage_path,
            "RESOURCE_SPACE_MODE": "fixture",
            "STORE_PRUNE_INTERVAL_SECONDS": "1",
        }
    )
    app = create_app(config)
    with TestClient(app, base_url="http://testserver"):
        time.sleep(1.2)
        pruned = json.loads(Path(storage_path).read_text())
        assert expired_token not in pruned["accessTokens"]

    if os.path.exists(storage_path):
        os.remove(storage_path)


def test_prune_interval_zero_skips_background_task() -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    config = create_config(
        {
            "APP_ENV": "development",
            "PORT": "0",
            "BASE_URL": "http://testserver",
            "OAUTH_ISSUER": "http://testserver",
            "OAUTH_CLIENT_ID": "canva-dev-app",
            "ASSET_SIGNING_SECRET": "test-signing-secret",
            "STORAGE_PATH": storage_path,
            "RESOURCE_SPACE_MODE": "fixture",
            "STORE_PRUNE_INTERVAL_SECONDS": "0",
        }
    )
    app = create_app(config)
    with TestClient(app, base_url="http://testserver"):
        pass
    assert app.state.deps.config.store_prune_interval_seconds == 0
    if os.path.exists(storage_path):
        os.remove(storage_path)


def test_background_prune_does_not_overwrite_corrupt_store() -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    corrupt = '{"authorizationCodes": {}, "accessTokens": {broken'
    Path(storage_path).write_text(corrupt)

    config = create_config(
        {
            "APP_ENV": "development",
            "PORT": "0",
            "BASE_URL": "http://testserver",
            "OAUTH_ISSUER": "http://testserver",
            "OAUTH_CLIENT_ID": "canva-dev-app",
            "ASSET_SIGNING_SECRET": "test-signing-secret",
            "STORAGE_PATH": storage_path,
            "RESOURCE_SPACE_MODE": "fixture",
            "STORE_PRUNE_INTERVAL_SECONDS": "1",
        }
    )
    app = create_app(config)
    with TestClient(app, base_url="http://testserver"):
        time.sleep(1.2)
        assert Path(storage_path).read_text() == corrupt

    if os.path.exists(storage_path):
        os.remove(storage_path)


def test_prune_strict_load_raises_without_writing() -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    Path(storage_path).write_text("{not-json")
    config = create_config({"STORAGE_PATH": storage_path})
    deps = build_dependencies(config)
    with pytest.raises(JsonStoreLoadError):
        deps.auth_service.prune()
    assert Path(storage_path).read_text() == "{not-json"
    if os.path.exists(storage_path):
        os.remove(storage_path)


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        json.dumps({"accessTokens": []}),
        json.dumps({"accessTokens": None}),
    ],
)
def test_prune_strict_load_rejects_invalid_store_shape(payload: str) -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    Path(storage_path).write_text(payload)
    config = create_config({"STORAGE_PATH": storage_path})
    deps = build_dependencies(config)
    with pytest.raises(JsonStoreLoadError):
        deps.auth_service.prune()
    assert Path(storage_path).read_text() == payload
    if os.path.exists(storage_path):
        os.remove(storage_path)
