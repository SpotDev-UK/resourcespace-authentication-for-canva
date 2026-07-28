"""Tests that structured log events fire with safe context and no secrets."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from resourcespace_platform.config import create_config
from resourcespace_platform.dependencies import build_dependencies
from resourcespace_platform.main import create_app

ACME_TENANT_URL = "https://acme.demo.resourcespace.local"
REDIRECT_URI = "https://example.com/oauth/callback"
STORAGE_KEY = Fernet.generate_key().decode()


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
        "RESOURCE_SPACE_SSO_ENABLED": "true",
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


def _initiate_sso(client: TestClient, *, challenge: str, canva_state: str = "canva-state-123") -> str:
    response = client.post(
        "/oauth/authorise",
        data={
            "auth_method": "sso",
            "client_id": "canva-dev-app",
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "state": canva_state,
            "scope": "openid dam:read",
            "code_challenge_method": "S256",
            "code_challenge": challenge,
            "tenant_url": ACME_TENANT_URL,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    return parse_qs(urlparse(response.headers["location"]).query)["state"][0]


def _sso_callback(
    client: TestClient,
    *,
    handoff_state: str | None,
    session_key: str | None = "fixture-sso-alice",
    username: str | None = "alice",
    fullname: str | None = "Alice Admin",
    email: str | None = None,
) -> Any:
    data: dict[str, str] = {}
    if handoff_state is not None:
        data["state"] = handoff_state
    if session_key is not None:
        data["sessionkey"] = session_key
    if username is not None:
        data["username"] = username
    if fullname is not None:
        data["fullname"] = fullname
    if email is not None:
        data["email"] = email
    return client.post("/oauth/sso/callback", data=data, follow_redirects=False)


def _find_logs(captured_logs: list[dict[str, Any]], message: str) -> list[dict[str, Any]]:
    return [entry for entry in captured_logs if entry.get("message") == message]


def _assert_log(
    captured_logs: list[dict[str, Any]],
    message: str,
    *,
    reason: str | None = None,
    allowed_context_keys: set[str] | None = None,
) -> dict[str, Any]:
    matches = _find_logs(captured_logs, message)
    assert matches, f"expected log event {message!r}, got {[e.get('message') for e in captured_logs]}"
    entry = matches[-1]
    context = entry.get("context") or {}
    if reason is not None:
        assert context.get("reason") == reason
    if allowed_context_keys is not None:
        assert set(context.keys()) <= allowed_context_keys
    return entry


def test_sso_happy_path_logs_share_correlation_id(captured_logs: list[dict[str, Any]]) -> None:
    for client, _ in _build_client():
        _, challenge = _pkce_pair()
        handoff_state = _initiate_sso(client, challenge=challenge)
        response = _sso_callback(client, handoff_state=handoff_state)
        assert response.status_code == 200, response.text

        initiated = _assert_log(
            captured_logs,
            "oauth_sso_initiated",
            allowed_context_keys={
                "correlationId",
                "clientId",
                "tenantHost",
                "transportPeerHash",
                "resolvedClientHostHash",
                "clientIpHeader",
                "clientIpHeaderTrusted",
                "clientIpHeaderPresent",
            },
        )
        succeeded = _assert_log(
            captured_logs,
            "oauth_sso_token_validation_succeeded",
            allowed_context_keys={"correlationId", "clientId", "tenantHost"},
        )
        completed = _assert_log(
            captured_logs,
            "oauth_sso_callback_completed",
            allowed_context_keys={"correlationId", "clientId", "tenantHost", "usernameProvided"},
        )
        correlation_id = initiated["context"]["correlationId"]
        assert succeeded["context"]["correlationId"] == correlation_id
        assert completed["context"]["correlationId"] == correlation_id
        _assert_log(
            captured_logs,
            "oauth_sso_callback_received",
            allowed_context_keys={
                "correlationId",
                "transportPeerHash",
                "resolvedClientHostHash",
                "clientIpHeader",
                "clientIpHeaderTrusted",
                "clientIpHeaderPresent",
            },
        )


@pytest.mark.parametrize(
    ("handoff_state", "reason"),
    [
        (None, "missing_state"),
        ("ssostate_unknown", "unknown_state"),
    ],
)
def test_sso_state_invalid_logs(
    captured_logs: list[dict[str, Any]], handoff_state: str | None, reason: str
) -> None:
    for client, _ in _build_client():
        _sso_callback(client, handoff_state=handoff_state)
        _assert_log(
            captured_logs,
            "oauth_sso_state_invalid",
            reason=reason,
            allowed_context_keys={"correlationId", "reason"},
        )


def test_sso_state_expired_logs(captured_logs: list[dict[str, Any]]) -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_PENDING_TTL_SECONDS="0"):
        _, challenge = _pkce_pair()
        handoff_state = _initiate_sso(client, challenge=challenge)
        time.sleep(0.01)
        _sso_callback(client, handoff_state=handoff_state)
        _assert_log(
            captured_logs,
            "oauth_sso_state_expired",
            allowed_context_keys={"correlationId"},
        )
        assert _find_logs(captured_logs, "oauth_sso_state_expired")


def test_sso_state_replay_logs(captured_logs: list[dict[str, Any]]) -> None:
    for client, _ in _build_client():
        _, challenge = _pkce_pair()
        handoff_state = _initiate_sso(client, challenge=challenge)
        assert _sso_callback(client, handoff_state=handoff_state).status_code == 200
        _sso_callback(client, handoff_state=handoff_state)
        _assert_log(
            captured_logs,
            "oauth_sso_state_replay",
            allowed_context_keys={"correlationId"},
        )


def test_sso_handoff_failed_logs(captured_logs: list[dict[str, Any]]) -> None:
    for client, _ in _build_client():
        _, challenge = _pkce_pair()
        handoff_state = _initiate_sso(client, challenge=challenge)
        _sso_callback(client, handoff_state=handoff_state, username=None)
        _assert_log(
            captured_logs,
            "oauth_sso_handoff_failed",
            reason="missing_username",
            allowed_context_keys={"correlationId", "reason"},
        )


@pytest.mark.parametrize(
    ("session_key", "reason"),
    [
        (None, "missing_sessionkey"),
        ("bogus", "UPSTREAM_SESSION_EXPIRED"),
    ],
)
def test_sso_token_validation_failed_logs(
    captured_logs: list[dict[str, Any]], session_key: str | None, reason: str
) -> None:
    for client, _ in _build_client():
        _, challenge = _pkce_pair()
        handoff_state = _initiate_sso(client, challenge=challenge)
        _sso_callback(client, handoff_state=handoff_state, session_key=session_key)
        _assert_log(
            captured_logs,
            "oauth_sso_token_validation_failed",
            reason=reason,
            allowed_context_keys={"correlationId", "clientId", "tenantHost", "reason"},
        )


def test_oauth_token_failed_logs(captured_logs: list[dict[str, Any]]) -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="false"):
        response = client.post(
            "/oauth/token",
            data={"grant_type": "authorization_code", "client_id": "canva-dev-app"},
        )
        assert response.status_code == 400
        _assert_log(
            captured_logs,
            "oauth_token_failed",
            allowed_context_keys={"error"},
        )


def test_auth_rejected_logs(captured_logs: list[dict[str, Any]]) -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="false"):
        response = client.post("/content/resources/find", json={"query": "logo"})
        assert response.status_code == 401
        _assert_log(
            captured_logs,
            "auth_rejected",
            reason="missing_bearer_token",
            allowed_context_keys={"path", "reason"},
        )


def test_canva_user_uninstall_failed_logs(captured_logs: list[dict[str, Any]]) -> None:
    for client, _ in _build_client(
        RESOURCE_SPACE_SSO_ENABLED="false",
        CANVA_REQUEST_VERIFICATION_MODE="off",
    ):
        response = client.post(
            "/webhooks/canva/user-uninstall",
            content=b"not-json",
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 400
        _assert_log(
            captured_logs,
            "canva_user_uninstall_failed",
            allowed_context_keys={"error"},
        )


def test_store_decrypt_failed_logs(captured_logs: list[dict[str, Any]]) -> None:
    key_a = Fernet.generate_key().decode()
    key_b = Fernet.generate_key().decode()
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    tokens: dict[str, Any] = {}

    config_a = create_config(
        {
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
    from datetime import datetime, timezone

    session = {
        "tenant": {"id": "tenant_acme", "slug": "acme", "name": "Acme", "baseUrl": ACME_TENANT_URL},
        "user": {"id": "tenant_acme:alice", "username": "alice", "displayName": "alice", "role": "member"},
        "upstream": {
            "mode": "live",
            "sessionKey": "rs-secret-session-key",
            "authenticatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }
    code = deps.auth_service.begin_authorization_from_session(
        client_id="canva-dev-app",
        redirect_uri=REDIRECT_URI,
        scope="openid dam:read",
        code_challenge=challenge,
        code_challenge_method="S256",
        session=session,
    )
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
    finally:
        client.close()

    config_b = create_config(
        {
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
        _assert_log(
            captured_logs,
            "store_decrypt_failed",
            allowed_context_keys={"bucket"},
        )
    if os.path.exists(storage_path):
        os.remove(storage_path)


def test_store_prune_failed_logs(
    captured_logs: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    config = create_config(
        {
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

    def _boom() -> None:
        raise RuntimeError("prune boom")

    monkeypatch.setattr(app.state.deps.auth_service, "prune", _boom)
    with TestClient(app, base_url="http://testserver") as client:
        time.sleep(1.2)
        client.get("/healthz")
    _assert_log(
        captured_logs,
        "store_prune_failed",
        allowed_context_keys={"error"},
    )
    if os.path.exists(storage_path):
        os.remove(storage_path)
