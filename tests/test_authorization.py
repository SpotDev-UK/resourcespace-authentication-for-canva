"""Authorization and permission regression tests (TC-06).

Covers bearer-token parsing, tenant isolation on direct-object access,
per-asset ACL enforcement, token revocation via the OAuth revoke endpoint,
and the unknown-tenant authorise path. Mirrors the harness and helpers in
`test_server.py` (TestClient, PKCE authorise + token exchange).
"""
from __future__ import annotations

import base64
import hashlib
import os
import tempfile
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from resourcespace_platform.config import create_config
from resourcespace_platform.main import create_app


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


def test_tampered_access_token_is_rejected(harness: tuple[TestClient, str]) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    # Flip the final character of the opaque token — server-side lookup must miss.
    good = tokens["access_token"]
    tampered = good[:-1] + ("A" if good[-1] != "A" else "B")
    response = client.get(
        "/api/session",
        headers={"Authorization": f"Bearer {tampered}"},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "SESSION_EXPIRED"


def test_missing_bearer_header_is_rejected(harness: tuple[TestClient, str]) -> None:
    client, _ = harness
    response = client.get("/api/session")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "MISSING_BEARER_TOKEN"


@pytest.mark.parametrize(
    "auth_header",
    [
        "Basic dXNlcjpwYXNz",
        "Token abc123",
        "bearer lowercase-scheme-should-fail",
        "",
    ],
)
def test_non_bearer_authorization_scheme_is_rejected(
    harness: tuple[TestClient, str], auth_header: str
) -> None:
    client, _ = harness
    response = client.get("/api/session", headers={"Authorization": auth_header})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "MISSING_BEARER_TOKEN"


def test_cross_tenant_direct_object_access_is_blocked(
    harness: tuple[TestClient, str],
) -> None:
    """Alice (tenant_acme) must not be able to fetch a tenant_globex asset by ID."""
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    # asset_globex_product belongs to tenant_globex, so Alice must not see it.
    response = client.post(
        "/content/resources/asset_globex_product/download-url",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code in (403, 404), response.text
    payload = response.json()
    assert payload["error"]["code"] in ("NOT_FOUND", "FORBIDDEN")
    # Critically: no download URL leaks through.
    assert "url" not in payload


def test_restricted_asset_access_requires_acl_membership(
    harness: tuple[TestClient, str],
) -> None:
    """Bob is an editor in tenant_acme; the confidential strategy asset is
    ACL-restricted to Alice only. Direct fetch by Bob must not succeed."""
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="bob",
        password="bob-password",
    )
    response = client.post(
        "/content/resources/asset_confidential_strategy/download-url",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code in (403, 404), response.text
    assert response.json()["error"]["code"] in ("FORBIDDEN", "NOT_FOUND")


def test_revoked_access_token_is_rejected_on_subsequent_use(
    harness: tuple[TestClient, str],
) -> None:
    client, _ = harness
    tokens = _authorize_as(
        client,
        tenant_url="https://acme.demo.resourcespace.local",
        username="alice",
        password="alice-password",
    )
    access_token = tokens["access_token"]

    before = client.get("/api/session", headers={"Authorization": f"Bearer {access_token}"})
    assert before.status_code == 200

    revoke = client.post("/oauth/revoke", data={"token": access_token})
    assert revoke.status_code == 200

    after = client.get("/api/session", headers={"Authorization": f"Bearer {access_token}"})
    assert after.status_code == 401
    assert after.json()["error"]["code"] == "SESSION_EXPIRED"


def test_unknown_tenant_url_is_rejected_without_crashing(
    harness: tuple[TestClient, str],
) -> None:
    client, _ = harness
    verifier, challenge = _pkce_pair()
    response = client.post(
        "/oauth/authorise",
        data={
            "client_id": "canva-dev-app",
            "redirect_uri": "https://example.com/oauth/callback",
            "response_type": "code",
            "state": "state-123",
            "scope": "openid dam:read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "tenant_url": "https://not-a-fixture-tenant.example.com",
            "username": "alice",
            "password": "alice-password",
        },
        follow_redirects=False,
    )
    # Fixture mode returns the authorise form re-rendered with UNKNOWN_TENANT.
    assert response.status_code == 403
    assert "UNKNOWN_TENANT" in response.text
    # No redirect to the client with a code must happen.
    assert "location" not in {k.lower() for k in response.headers.keys()}
    _ = verifier  # silence lint; PKCE challenge is all we need here
