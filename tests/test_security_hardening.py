"""Regression tests for the security-hardening pass.

Covers the production-config validator, OAuth client_id / redirect_uri /
PKCE-method enforcement, manual-OAuth gating outside dev/test, scope
enforcement on read endpoints, refresh-token rotation with grace, the
SSRF protections on the upload helper, and the metrics-token gate.
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

from resourcespace_platform.config import (
    ConfigValidationError,
    create_config,
    validate_config_for_environment,
)
from resourcespace_platform.main import create_app
from resourcespace_platform.services.resourcespace._upload import _validate_export_url


def _production_env(**overrides: str) -> dict[str, str]:
    from cryptography.fernet import Fernet

    env = {
        "APP_ENV": "production",
        "CANVA_REQUEST_VERIFICATION_MODE": "required",
        "CANVA_CLIENT_SECRET": base64.b64encode(b"a-secret").decode("ascii"),
        "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
        "OAUTH_CLIENT_ID": "real-canva-client",
        "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
        "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
        "STORAGE_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
            [{"id": "acme-prod", "baseUrl": "https://acme.demo.resourcespace.local"}]
        ),
    }
    env.update(overrides)
    return env


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


def _authorize(client: TestClient, *, scope: str = "openid dam:read") -> dict[str, Any]:
    verifier, challenge = _pkce_pair()
    redirect_uri = "https://example.com/oauth/callback"
    response = client.post(
        "/oauth/authorise",
        data={
            "client_id": "canva-dev-app",
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "state": "state-123",
            "scope": scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "tenant_url": "https://acme.demo.resourcespace.local",
            "username": "alice",
            "password": "alice-password",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302, response.text
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
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


# --- Config validator -------------------------------------------------------


def test_validator_passes_in_development() -> None:
    config = create_config({"APP_ENV": "development"})
    validate_config_for_environment(config)


def test_validator_rejects_production_with_default_secrets() -> None:
    config = create_config({"APP_ENV": "production"})
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    message = str(info.value)
    assert "CANVA_REQUEST_VERIFICATION_MODE" in message
    assert "CANVA_CLIENT_SECRET" in message
    assert "OAUTH_REDIRECT_URI_ALLOWLIST" in message
    assert "CORS_ORIGIN" in message
    assert "STORAGE_ENCRYPTION_KEY" in message


def test_validator_passes_with_full_production_config() -> None:
    config = create_config(_production_env())
    validate_config_for_environment(config)


def test_validator_rejects_invalid_oauth_clients_json() -> None:
    config = create_config(_production_env(OAUTH_CLIENTS_JSON="not-json"))

    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "OAUTH_CLIENTS_JSON" in str(info.value)


def test_validator_accepts_comma_separated_cors_origin() -> None:
    config = create_config(
        _production_env(CORS_ORIGIN="https://app-aaaaaa.canva-apps.com,https://www.canva.com")
    )
    validate_config_for_environment(config)


def test_validator_rejects_wildcard_inside_cors_origin_list() -> None:
    config = create_config(_production_env(CORS_ORIGIN="https://app-aaaaaa.canva-apps.com,*"))
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "CORS_ORIGIN" in str(info.value)


def test_validator_accepts_default_client_id_when_explicitly_allowed() -> None:
    config = create_config(
        _production_env(
            OAUTH_CLIENT_ID="canva-dev-app",
            OAUTH_ALLOW_DEFAULT_CLIENT_ID="true",
            OAUTH_REDIRECT_URI_ALLOWLIST="https://www.canva.com/apps/oauth/authorized",
        )
    )
    validate_config_for_environment(config)


def test_validator_still_rejects_empty_client_id_even_with_override() -> None:
    config = create_config(
        _production_env(
            OAUTH_CLIENT_ID="",
            OAUTH_ALLOW_DEFAULT_CLIENT_ID="true",
            OAUTH_REDIRECT_URI_ALLOWLIST="https://example/callback",
            CORS_ORIGIN="https://app.example",
        )
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "OAUTH_CLIENT_ID" in str(info.value)


def test_validator_passes_live_mode_with_tenant_registry_only() -> None:
    config = create_config(_production_env(RESOURCE_SPACE_MODE="live"))
    validate_config_for_environment(config)


def test_validator_passes_with_approved_resourcespace_suffix_and_empty_registry() -> None:
    config = create_config(
        _production_env(
            RESOURCE_SPACE_MODE="live",
            RESOURCE_SPACE_TENANTS_JSON="[]",
            RESOURCE_SPACE_ALLOWED_HOSTS=".resourcespace.com",
        )
    )
    validate_config_for_environment(config)


def test_validator_rejects_unknown_resource_space_mode() -> None:
    config = create_config(_production_env(RESOURCE_SPACE_MODE="banana"))
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    message = str(info.value)
    assert "RESOURCE_SPACE_MODE" in message


# --- OAuth route hardening --------------------------------------------------


def test_oauth_authorize_rejects_unknown_client_id() -> None:
    for client, _ in _build_client():
        verifier, challenge = _pkce_pair()
        response = client.post(
            "/oauth/authorise",
            data={
                "client_id": "wrong-client",
                "redirect_uri": "https://example.com/oauth/callback",
                "response_type": "code",
                "state": "s",
                "scope": "openid dam:read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "tenant_url": "https://acme.demo.resourcespace.local",
                "username": "alice",
                "password": "alice-password",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_CLIENT"


def test_oauth_authorize_enforces_redirect_uri_allowlist() -> None:
    overrides = {"OAUTH_REDIRECT_URI_ALLOWLIST": "https://allowed.example/callback"}
    for client, _ in _build_client(**overrides):
        verifier, challenge = _pkce_pair()
        response = client.post(
            "/oauth/authorise",
            data={
                "client_id": "canva-dev-app",
                "redirect_uri": "https://attacker.example/callback",
                "response_type": "code",
                "state": "s",
                "scope": "openid dam:read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "tenant_url": "https://acme.demo.resourcespace.local",
                "username": "alice",
                "password": "alice-password",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REDIRECT_URI"


def test_oauth_authorize_accepts_configured_secondary_client() -> None:
    clients_json = json.dumps(
        [
            {
                "clientId": "partner-client",
                "integration": "partner-integration",
                "redirectUriAllowlist": ["https://partner.example/callback"],
            }
        ]
    )
    overrides = {"OAUTH_CLIENTS_JSON": clients_json}
    for client, storage_path in _build_client(**overrides):
        verifier, challenge = _pkce_pair()
        redirect_uri = "https://partner.example/callback"
        response = client.post(
            "/oauth/authorise",
            data={
                "client_id": "partner-client",
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "state": "s",
                "scope": "openid dam:read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "tenant_url": "https://acme.demo.resourcespace.local",
                "username": "alice",
                "password": "alice-password",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302, response.text
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]

        token_response = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "partner-client",
                "redirect_uri": redirect_uri,
                "code": code,
                "code_verifier": verifier,
            },
        )
        assert token_response.status_code == 200, token_response.text
        token = token_response.json()["access_token"]

        state = json.loads(Path(storage_path).read_text())
        record = state["accessTokens"][token]
        assert record["integration"] == "partner-integration"
        assert record["session"]["broker"] == {
            "clientId": "partner-client",
            "integration": "partner-integration",
        }


def test_oauth_authorize_rejects_cross_client_redirect_uri() -> None:
    clients_json = json.dumps(
        [
            {
                "clientId": "partner-client",
                "integration": "partner-integration",
                "redirectUriAllowlist": ["https://partner.example/callback"],
            }
        ]
    )
    overrides = {
        "OAUTH_CLIENTS_JSON": clients_json,
        "OAUTH_REDIRECT_URI_ALLOWLIST": "https://canva.example/callback",
    }
    for client, _ in _build_client(**overrides):
        verifier, challenge = _pkce_pair()
        response = client.post(
            "/oauth/authorise",
            data={
                "client_id": "partner-client",
                "redirect_uri": "https://canva.example/callback",
                "response_type": "code",
                "state": "s",
                "scope": "openid dam:read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "tenant_url": "https://acme.demo.resourcespace.local",
                "username": "alice",
                "password": "alice-password",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REDIRECT_URI"


def test_removed_oauth_client_cannot_use_existing_tokens() -> None:
    fd, storage_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(storage_path)
    clients_json = json.dumps(
        [
            {
                "clientId": "partner-client",
                "integration": "partner-integration",
                "redirectUriAllowlist": ["https://partner.example/callback"],
            }
        ]
    )
    base_env: dict[str, str] = {
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

    try:
        active_config = create_config({**base_env, "OAUTH_CLIENTS_JSON": clients_json})
        active_client = TestClient(create_app(active_config), base_url="http://testserver")
        try:
            verifier, challenge = _pkce_pair()
            redirect_uri = "https://partner.example/callback"
            response = active_client.post(
                "/oauth/authorise",
                data={
                    "client_id": "partner-client",
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "state": "s",
                    "scope": "openid dam:read",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "tenant_url": "https://acme.demo.resourcespace.local",
                    "username": "alice",
                    "password": "alice-password",
                },
                follow_redirects=False,
            )
            assert response.status_code == 302, response.text
            code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
            token_response = active_client.post(
                "/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": "partner-client",
                    "redirect_uri": redirect_uri,
                    "code": code,
                    "code_verifier": verifier,
                },
            )
            assert token_response.status_code == 200, token_response.text
            tokens = token_response.json()
        finally:
            active_client.close()

        removed_config = create_config(base_env)
        removed_client = TestClient(create_app(removed_config), base_url="http://testserver")
        try:
            refresh = removed_client.post(
                "/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": "partner-client",
                    "refresh_token": tokens["refresh_token"],
                },
            )
            assert refresh.status_code == 400
            assert refresh.json()["error"] == "invalid_client"

            find = removed_client.post(
                "/content/resources/find",
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
                json={"types": ["CONTAINER"], "limit": 1},
            )
            assert find.status_code == 401
            assert find.json()["error"]["code"] == "SESSION_EXPIRED"
        finally:
            removed_client.close()
    finally:
        if os.path.exists(storage_path):
            os.remove(storage_path)


def test_oauth_authorize_rejects_plain_pkce() -> None:
    for client, _ in _build_client():
        response = client.post(
            "/oauth/authorise",
            data={
                "client_id": "canva-dev-app",
                "redirect_uri": "https://example.com/oauth/callback",
                "response_type": "code",
                "state": "s",
                "scope": "openid dam:read",
                "code_challenge": "irrelevant",
                "code_challenge_method": "plain",
                "tenant_url": "https://acme.demo.resourcespace.local",
                "username": "alice",
                "password": "alice-password",
            },
            follow_redirects=False,
        )
        assert response.status_code == 400
        assert "S256" in response.json()["error"]["message"]


# --- Manual mode gating -----------------------------------------------------


def test_manual_callback_returns_404_outside_dev() -> None:
    overrides = _production_env(
        APP_ENV="staging",
        OAUTH_CLIENT_ID="real",
        OAUTH_REDIRECT_URI_ALLOWLIST="https://allowed/callback",
        CORS_ORIGIN="https://app.example",
        ASSET_SIGNING_SECRET="long-random",
    )
    for client, _ in _build_client(**overrides):
        response = client.get(
            "/oauth/manual/callback",
            params={"code": "x", "state": "manual-fixture-auth"},
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


# --- Scope enforcement ------------------------------------------------------


def test_content_find_requires_dam_read_scope() -> None:
    for client, _ in _build_client():
        tokens = _authorize(client, scope="openid")
        response = client.post(
            "/content/resources/find",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
            json={"types": ["IMAGE"]},
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INSUFFICIENT_SCOPE"


# --- Refresh-token rotation -------------------------------------------------


def test_refresh_rotates_token_and_grace_replay_is_idempotent() -> None:
    overrides = {"OAUTH_REFRESH_GRACE_SECONDS": "60"}
    for client, _ in _build_client(**overrides):
        tokens = _authorize(client)
        first_refresh = tokens["refresh_token"]

        response = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "canva-dev-app",
                "refresh_token": first_refresh,
            },
        )
        assert response.status_code == 200
        rotated = response.json()
        assert rotated["refresh_token"] != first_refresh

        replay = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "canva-dev-app",
                "refresh_token": first_refresh,
            },
        )
        assert replay.status_code == 200, replay.text
        assert replay.json()["refresh_token"] == rotated["refresh_token"]
        assert replay.json()["access_token"] == rotated["access_token"]


def test_webhook_rejects_unsigned_request_in_smart_mode() -> None:
    for client, _ in _build_client(CANVA_REQUEST_VERIFICATION_MODE="smart"):
        response = client.post(
            "/webhooks/canva/user-uninstall",
            json={"user_id": "user_alice", "tenant_id": "tenant_acme"},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "INVALID_CANVA_SIGNATURE"


def test_railway_rejects_development_app_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RAILWAY_ENVIRONMENT", "production")
    config = create_config({"APP_ENV": "development"})
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "Railway" in str(info.value)


def test_omitted_app_env_defaults_to_production_and_validates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    config = create_config({})
    assert config.environment == "production"
    with pytest.raises(ConfigValidationError):
        validate_config_for_environment(config)


def test_revoked_refresh_without_rotation_response_rejected_within_grace() -> None:
    overrides = {"OAUTH_REFRESH_GRACE_SECONDS": "60", "CANVA_REQUEST_VERIFICATION_MODE": "off"}
    for client, _ in _build_client(**overrides):
        tokens = _authorize(client)
        refresh_token = tokens["refresh_token"]
        uninstall = client.post(
            "/webhooks/canva/user-uninstall",
            json={"user_id": "user_alice", "tenant_id": "tenant_acme"},
        )
        assert uninstall.status_code == 200
        replay = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "canva-dev-app",
                "refresh_token": refresh_token,
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


def test_refresh_outside_grace_window_rejected() -> None:
    overrides = {"OAUTH_REFRESH_GRACE_SECONDS": "0"}
    for client, _ in _build_client(**overrides):
        tokens = _authorize(client)
        first_refresh = tokens["refresh_token"]
        first = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "canva-dev-app",
                "refresh_token": first_refresh,
            },
        )
        assert first.status_code == 200
        replay = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "canva-dev-app",
                "refresh_token": first_refresh,
            },
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


# --- Upload SSRF guard ------------------------------------------------------


def test_validate_export_url_rejects_http() -> None:
    config = create_config({})
    with pytest.raises(Exception) as info:
        _validate_export_url("http://export.example/file.png", config)
    assert "https" in str(info.value).lower()


def test_validate_export_url_rejects_private_host() -> None:
    config = create_config({})
    with pytest.raises(Exception) as info:
        _validate_export_url("https://localhost/file.png", config)
    assert "private" in str(info.value).lower()


def test_validate_export_url_enforces_allowlist() -> None:
    config = create_config({"CANVA_UPLOAD_ALLOWED_HOSTS": "export.canva.com"})
    with pytest.raises(Exception) as info:
        _validate_export_url("https://attacker.example/file.png", config)
    assert "CANVA_UPLOAD_ALLOWED_HOSTS" in str(info.value)


# --- Storage permissions ----------------------------------------------------


def test_json_store_chmod_failure_fatal_when_secure_permissions_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from resourcespace_platform.services.json_store import JsonStore

    def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise OSError("chmod not supported on this filesystem")

    monkeypatch.setattr("resourcespace_platform.services.json_store.os.chmod", _boom)

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.remove(path)
    try:
        # Dev/test default tolerates a failed chmod so local work is frictionless.
        JsonStore(path)
        os.remove(path)
        # Outside dev/test a failed chmod on the cleartext store is fatal.
        with pytest.raises(RuntimeError) as info:
            JsonStore(path, require_secure_permissions=True)
        assert "permissions" in str(info.value).lower()
    finally:
        if os.path.exists(path):
            os.remove(path)


def test_json_store_restricts_existing_world_readable_file_on_startup() -> None:
    import stat

    from resourcespace_platform.services.json_store import JsonStore

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        # Simulate a store left world-readable by a prior deploy / manual edit.
        Path(path).write_text("{}")
        os.chmod(path, 0o644)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o644

        # Constructing the store must re-restrict the existing file, not just
        # new ones.
        JsonStore(path)
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    finally:
        if os.path.exists(path):
            os.remove(path)


# --- Metrics gating ---------------------------------------------------------


def test_metrics_returns_aggregate_only_without_token() -> None:
    for client, _ in _build_client():
        response = client.get("/metrics")
        assert response.status_code == 200
        body = response.json()
        assert "auth" in body
        assert "requestVerificationMode" not in body
        assert "environment" not in body


def test_metrics_full_payload_requires_bearer_token() -> None:
    for client, _ in _build_client(METRICS_TOKEN="mt-secret"):
        unauth = client.get("/metrics")
        assert unauth.status_code == 401
        ok = client.get("/metrics", headers={"Authorization": "Bearer mt-secret"})
        assert ok.status_code == 200
        assert ok.json()["requestVerificationMode"] == "smart"


# --- Public health/root info hiding ----------------------------------------


def test_production_fixture_sso_rejects_unregistered_tenant_url() -> None:
    """Outside dev/test, SSO must not redirect to a synthesized tenant host."""
    overrides = _production_env(
        RESOURCE_SPACE_MODE="fixture",
        RESOURCE_SPACE_SSO_ENABLED="true",
    )
    for client, _ in _build_client(**overrides):
        _, challenge = _pkce_pair()
        response = client.post(
            "/oauth/authorise",
            data={
                "auth_method": "sso",
                "client_id": "real-canva-client",
                "redirect_uri": "https://example.canva-apps.com/oauth/callback",
                "response_type": "code",
                "state": "canva-state",
                "scope": "openid dam:read",
                "code_challenge_method": "S256",
                "code_challenge": challenge,
                "tenant_url": "https://attacker.example",
            },
            follow_redirects=False,
        )
        assert response.status_code == 403, response.text
        assert "UNKNOWN_TENANT" in response.text


def test_production_sso_binds_approved_resourcespace_tenant_to_pending_state() -> None:
    overrides = _production_env(
        RESOURCE_SPACE_MODE="fixture",
        RESOURCE_SPACE_SSO_ENABLED="true",
        RESOURCE_SPACE_TENANTS_JSON="[]",
        RESOURCE_SPACE_ALLOWED_HOSTS=".resourcespace.com",
    )
    for client, storage_path in _build_client(**overrides):
        _, challenge = _pkce_pair()
        response = client.post(
            "/oauth/authorise",
            data={
                "auth_method": "sso",
                "client_id": "real-canva-client",
                "redirect_uri": "https://example.canva-apps.com/oauth/callback",
                "response_type": "code",
                "state": "canva-state",
                "scope": "openid dam:read",
                "code_challenge_method": "S256",
                "code_challenge": challenge,
                "tenant_url": "https://SpotDev.Free.ResourceSpace.com/login.php",
            },
            follow_redirects=False,
        )

        assert response.status_code == 302, response.text
        location = response.headers["location"]
        handoff_state = parse_qs(urlparse(location).query)["state"][0]
        store = json.loads(Path(storage_path).read_text())
        pending = store["pendingSsoStates"][handoff_state]
        assert pending["tenant"]["baseUrl"] == "https://spotdev.free.resourcespace.com"
        assert pending["tenant"]["apiUrl"] == "https://spotdev.free.resourcespace.com/api/"
        assert location.startswith(
            "https://spotdev.free.resourcespace.com/pages/user/user_api_session.php?"
        )


def test_root_does_not_leak_environment_or_mode() -> None:
    for client, _ in _build_client():
        response = client.get("/")
        body = response.json()
        assert "environment" not in body
        assert "resourceSpaceMode" not in body


def test_healthz_minimal() -> None:
    for client, _ in _build_client():
        body = client.get("/healthz").json()
        assert body == {"ok": True}
