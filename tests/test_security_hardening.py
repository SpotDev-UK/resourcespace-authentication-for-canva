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


def _pkce_pair() -> tuple[str, str]:
    verifier = "verifier-value-123456789"
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _build_client(**overrides: str) -> Iterator[tuple[TestClient, str]]:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    env: dict[str, str] = {
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


def test_validator_passes_with_full_production_config() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": base64.b64encode(b"a-secret").decode("ascii"),
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
        }
    )
    validate_config_for_environment(config)


def test_validator_rejects_invalid_oauth_clients_json() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": base64.b64encode(b"a-secret").decode("ascii"),
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "OAUTH_CLIENTS_JSON": "not-json",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
        }
    )

    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "OAUTH_CLIENTS_JSON" in str(info.value)


def test_validator_accepts_comma_separated_cors_origin() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": base64.b64encode(b"a-secret").decode("ascii"),
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com,https://www.canva.com",
        }
    )
    validate_config_for_environment(config)


def test_validator_rejects_wildcard_inside_cors_origin_list() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": base64.b64encode(b"a-secret").decode("ascii"),
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "real-canva-client",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example.canva-apps.com/oauth/callback",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com,*",
        }
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "CORS_ORIGIN" in str(info.value)


def test_validator_accepts_default_client_id_when_explicitly_allowed() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": base64.b64encode(b"a-secret").decode("ascii"),
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "canva-dev-app",
            "OAUTH_ALLOW_DEFAULT_CLIENT_ID": "true",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://www.canva.com/apps/oauth/authorized",
            "CORS_ORIGIN": "https://app-aaaaaa.canva-apps.com",
        }
    )
    validate_config_for_environment(config)


def test_validator_still_rejects_empty_client_id_even_with_override() -> None:
    config = create_config(
        {
            "APP_ENV": "production",
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_CLIENT_SECRET": base64.b64encode(b"a-secret").decode("ascii"),
            "ASSET_SIGNING_SECRET": "long-random-asset-secret-value",
            "OAUTH_CLIENT_ID": "",
            "OAUTH_ALLOW_DEFAULT_CLIENT_ID": "true",
            "OAUTH_REDIRECT_URI_ALLOWLIST": "https://example/callback",
            "CORS_ORIGIN": "https://app.example",
        }
    )
    with pytest.raises(ConfigValidationError) as info:
        validate_config_for_environment(config)
    assert "OAUTH_CLIENT_ID" in str(info.value)


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
    overrides = {
        "APP_ENV": "staging",
        "CANVA_REQUEST_VERIFICATION_MODE": "required",
        "CANVA_CLIENT_SECRET": base64.b64encode(b"x").decode("ascii"),
        "ASSET_SIGNING_SECRET": "long-random",
        "OAUTH_CLIENT_ID": "real",
        "OAUTH_REDIRECT_URI_ALLOWLIST": "https://allowed/callback",
        "CORS_ORIGIN": "https://app.example",
    }
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


def test_refresh_rotates_token_and_old_within_grace_still_works() -> None:
    overrides = {"OAUTH_REFRESH_GRACE_SECONDS": "60"}
    for client, _ in _build_client(**overrides):
        tokens = _authorize(client)
        first_refresh = tokens["refresh_token"]

        # First refresh issues a new refresh_token (rotation)
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

        # Replaying the original refresh token within the grace window still
        # works (handles concurrent refresh attempts).
        replay = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "canva-dev-app",
                "refresh_token": first_refresh,
            },
        )
        assert replay.status_code == 200, replay.text


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
