"""Regression tests for the ResourceSpace hosted-login (SSO) handoff.

Covers the SSO feature flag gating, the initiation leg (``POST
/oauth/authorise`` with ``auth_method=sso``), the callback leg (``POST
/oauth/sso/callback``) and its handoff-state state machine (invalid,
expired, replayed, valid), and the subsequent authorization-code ->
access-token exchange. Mirrors the harness/helper conventions in
`test_security_hardening.py` (`_build_client`, `_pkce_pair`, reading the
JSON store file directly) and the authorize/token roundtrip conventions in
`test_server.py` / `test_authorization.py` (`_authorize_as`).
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
from resourcespace_platform.main import create_app

ACME_TENANT_URL = "https://acme.demo.resourcespace.local"
GLOBEX_TENANT_URL = "https://globex.demo.resourcespace.local"
REDIRECT_URI = "https://example.com/oauth/callback"


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


def _read_store(storage_path: str) -> dict[str, Any]:
    return json.loads(Path(storage_path).read_text())


def _initiate_sso(
    client: TestClient,
    *,
    challenge: str,
    canva_state: str = "canva-state-123",
    tenant_url: str = ACME_TENANT_URL,
    redirect_uri: str = REDIRECT_URI,
    client_id: str = "canva-dev-app",
    scope: str = "openid dam:read",
    code_challenge: str | None = None,
    omit_code_challenge: bool = False,
) -> Any:
    """POST the SSO-initiation form. Returns the raw TestClient response."""
    data: dict[str, str] = {
        "auth_method": "sso",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "state": canva_state,
        "scope": scope,
        "code_challenge_method": "S256",
        "tenant_url": tenant_url,
    }
    if not omit_code_challenge:
        data["code_challenge"] = code_challenge if code_challenge is not None else challenge
    return client.post("/oauth/authorise", data=data, follow_redirects=False)


def _extract_handoff_state(location: str) -> str:
    """Pull the broker-generated handoff state out of the RS-bound redirect
    Location, e.g. .../user_api_session.php?system=canva&state=ssostate_...."""
    parsed = urlparse(location)
    return parse_qs(parsed.query)["state"][0]


def _sso_callback(
    client: TestClient,
    *,
    handoff_state: str | None,
    session_key: str | None = "fixture-sso-alice",
    username: str | None = "alice",
    fullname: str | None = "Alice Admin",
    email: str | None = None,
) -> Any:
    """POST the SSO callback (simulating the ResourceSpace hosted-login
    redirect back to the broker). Returns the raw TestClient response."""
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


def _run_full_sso_initiation(
    client: TestClient,
    *,
    canva_state: str = "canva-state-123",
    tenant_url: str = ACME_TENANT_URL,
    redirect_uri: str = REDIRECT_URI,
) -> tuple[str, str, str]:
    """Initiate SSO and return (handoff_state, verifier, redirect_uri)."""
    verifier, challenge = _pkce_pair()
    response = _initiate_sso(
        client,
        challenge=challenge,
        canva_state=canva_state,
        tenant_url=tenant_url,
        redirect_uri=redirect_uri,
    )
    assert response.status_code == 302, response.text
    handoff_state = _extract_handoff_state(response.headers["location"])
    return handoff_state, verifier, redirect_uri


def _exchange_code_for_tokens(
    client: TestClient, *, code: str, verifier: str, redirect_uri: str = REDIRECT_URI
) -> dict[str, Any]:
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


# --- 1. SSO button visibility on the authorize page ------------------------


def test_sso_button_hidden_when_flag_off() -> None:
    for client, _ in _build_client():
        response = client.get("/oauth/authorise")
        assert response.status_code == 200
        assert "single sign-on" not in response.text.lower()


def test_sso_button_present_when_flag_on() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        response = client.get("/oauth/authorise")
        assert response.status_code == 200
        assert "single sign-on" in response.text.lower()


# --- 2. Callback gating when the flag is off --------------------------------


def test_sso_callback_returns_404_when_flag_off() -> None:
    for client, _ in _build_client():
        response = _sso_callback(client, handoff_state="whatever")
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


# --- 3. Forged auth_method=sso while the flag is off ------------------------


def test_forged_sso_auth_method_rejected_when_flag_off() -> None:
    for client, _ in _build_client():
        verifier, challenge = _pkce_pair()
        response = _initiate_sso(client, challenge=challenge)
        assert response.status_code == 400
        assert "SSO_DISABLED" in response.text
        _ = verifier


# --- 4. Initiation requires code_challenge ----------------------------------


def test_sso_initiation_without_code_challenge_is_rejected() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        response = _initiate_sso(client, challenge=challenge, omit_code_challenge=True)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"


# --- 5. Initiation happy path: 302 to the RS hosted-login endpoint ----------


def test_sso_initiation_happy_path_redirects_to_resourcespace() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        verifier, challenge = _pkce_pair()
        response = _initiate_sso(client, challenge=challenge)
        assert response.status_code == 302, response.text
        location = response.headers["location"]
        parsed = urlparse(location)
        assert parsed.scheme == "https"
        assert parsed.netloc == "acme.demo.resourcespace.local"
        assert parsed.path == "/pages/user/user_api_session.php"
        query = parse_qs(parsed.query)
        assert query["system"] == ["canva"]
        assert query["state"][0].startswith("ssostate_")
        _ = verifier


# --- 6. Blank tenant_url re-renders the authorize page with an error -------


def test_sso_initiation_with_blank_tenant_url_rerenders_authorize_page() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        response = _initiate_sso(client, challenge=challenge, tenant_url="")
        # get_configured_tenant() rejects a blank tenant_url with
        # INVALID_TENANT_URL (400); the authorize page is re-rendered rather
        # than redirecting to ResourceSpace.
        assert response.status_code == 400, response.text
        assert "text/html" in response.headers["content-type"]
        assert "INVALID_TENANT_URL" in response.text
        assert "location" not in {k.lower() for k in response.headers.keys()}


# --- 7 & 8. Full fixture E2E + canva state preservation ---------------------


def test_full_fixture_sso_end_to_end_flow() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        canva_state = "canva-state-e2e"
        handoff_state, verifier, redirect_uri = _run_full_sso_initiation(
            client, canva_state=canva_state
        )

        callback = _sso_callback(client, handoff_state=handoff_state)
        # ResourceSpace calls the callback server-side and treats only HTTP 200 as
        # success. redirectUrl carries the Canva completion target; with the RS SSO
        # redirect patch the browser follows a 303 to that URL.
        assert callback.status_code == 200, callback.text
        # The response carries a fresh authorization code, so it must not be
        # cacheable by any intermediary.
        assert callback.headers.get("cache-control") == "no-store"
        body = callback.json()
        completion = urlparse(body["redirectUrl"])
        query = parse_qs(completion.query)
        assert "code" in query
        assert query["state"] == [canva_state]

        code = query["code"][0]
        tokens = _exchange_code_for_tokens(client, code=code, verifier=verifier, redirect_uri=redirect_uri)
        assert tokens["access_token"]

        session = client.get(
            "/api/session",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        assert session.status_code == 200, session.text
        payload = session.json()
        assert payload["user"]["username"] == "alice"
        assert payload["tenant"]["id"] == "tenant_acme"

        _ = storage_path


# --- 9. Missing state --------------------------------------------------------


def test_sso_callback_missing_state_is_rejected() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        response = _sso_callback(client, handoff_state=None)
        assert response.status_code == 400
        assert response.json()["reason"] == "sso_state_invalid"


# --- 10. Unknown state -------------------------------------------------------


def test_sso_callback_unknown_state_is_rejected() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        response = _sso_callback(client, handoff_state="ssostate_does_not_exist")
        assert response.status_code == 400
        assert response.json()["reason"] == "sso_state_invalid"


# --- 11. Expired state --------------------------------------------------------


def test_sso_callback_expired_state_is_rejected() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(client)

        state = _read_store(storage_path)
        record = state["pendingSsoStates"][handoff_state]
        record["expiresAt"] = 0  # force expiry, but leave purgeAt untouched
        Path(storage_path).write_text(json.dumps(state, indent=2))

        response = _sso_callback(client, handoff_state=handoff_state)
        assert response.status_code == 400
        assert response.json()["reason"] == "sso_state_expired"


# --- 12. Replayed state -------------------------------------------------------


def test_sso_callback_replayed_state_is_rejected() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(client)

        first = _sso_callback(client, handoff_state=handoff_state)
        assert first.status_code == 200, first.text

        replay = _sso_callback(client, handoff_state=handoff_state)
        assert replay.status_code == 400
        assert replay.json()["reason"] == "sso_state_replay"


# --- 13. Missing username -----------------------------------------------------


def test_sso_callback_missing_username_is_rejected() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(client)

        response = _sso_callback(client, handoff_state=handoff_state, username=None)
        assert response.status_code == 400
        assert response.json()["reason"] == "sso_handoff_failed"
        record = _read_store(storage_path)["pendingSsoStates"][handoff_state]
        assert record.get("usedAt") is None

        retry = _sso_callback(client, handoff_state=handoff_state)
        assert retry.status_code == 200, retry.text


# --- 14. Missing sessionkey -> validation failure ----------------------------


def test_sso_callback_missing_sessionkey_is_rejected() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(client)

        response = _sso_callback(client, handoff_state=handoff_state, session_key=None)
        assert response.status_code == 401, response.text
        assert response.json()["reason"] == "resourcespace_token_validation_failed"
        assert _read_store(storage_path)["pendingSsoStates"][handoff_state].get("usedAt") is None

        retry = _sso_callback(client, handoff_state=handoff_state)
        assert retry.status_code == 200, retry.text


# --- 15. Invalid sessionkey -> validation failure (no code minted) -----------


def test_sso_callback_invalid_sessionkey_is_rejected() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(client)

        response = _sso_callback(client, handoff_state=handoff_state, session_key="bogus")
        assert response.status_code == 401, response.text
        assert response.json()["reason"] == "resourcespace_token_validation_failed"
        # A failed validation must not mint a broker authorization code.
        assert _read_store(storage_path)["authorizationCodes"] == {}
        assert _read_store(storage_path)["pendingSsoStates"][handoff_state].get("usedAt") is None

        retry = _sso_callback(client, handoff_state=handoff_state)
        assert retry.status_code == 200, retry.text


# --- 16. GET callback is not allowed -----------------------------------------


def test_sso_callback_get_method_not_allowed() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        response = client.get("/oauth/sso/callback")
        assert response.status_code == 405


# --- 17. Tombstone retention after a successful callback --------------------


def test_sso_successful_callback_retains_tombstoned_state() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(client)

        response = _sso_callback(client, handoff_state=handoff_state)
        assert response.status_code == 200, response.text

        state = _read_store(storage_path)
        record = state["pendingSsoStates"].get(handoff_state)
        assert record is not None
        assert record["usedAt"] is not None


# --- 18. Password flow unaffected by the SSO flag ----------------------------


def test_password_flow_still_works_with_sso_flag_on() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        verifier, challenge = _pkce_pair()
        response = client.post(
            "/oauth/authorise",
            data={
                "client_id": "canva-dev-app",
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "state": "state-password-on",
                "scope": "openid dam:read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "tenant_url": ACME_TENANT_URL,
                "username": "alice",
                "password": "alice-password",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302, response.text
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        tokens = _exchange_code_for_tokens(client, code=code, verifier=verifier)
        assert tokens["access_token"]


def test_password_flow_still_works_with_sso_flag_off() -> None:
    for client, _ in _build_client():
        verifier, challenge = _pkce_pair()
        response = client.post(
            "/oauth/authorise",
            data={
                "client_id": "canva-dev-app",
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "state": "state-password-off",
                "scope": "openid dam:read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "tenant_url": ACME_TENANT_URL,
                "username": "alice",
                "password": "alice-password",
            },
            follow_redirects=False,
        )
        assert response.status_code == 302, response.text
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        tokens = _exchange_code_for_tokens(client, code=code, verifier=verifier)
        assert tokens["access_token"]


# --- 19. Wrong-tenant fixture key --------------------------------------------


def test_sso_callback_wrong_tenant_sessionkey_is_rejected() -> None:
    """The handoff was initiated against acme, but the callback presents a
    session key that belongs to a globex fixture user. Tenant-binding
    validation in `_authenticate_fixture_sso` must fail closed."""
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(
            client, tenant_url=ACME_TENANT_URL
        )

        response = _sso_callback(
            client,
            handoff_state=handoff_state,
            session_key="fixture-sso-clara",
            username="clara",
        )
        assert response.status_code == 401, response.text
        assert response.json()["reason"] == "resourcespace_token_validation_failed"
        assert _read_store(storage_path)["authorizationCodes"] == {}


# --- 20. HTTPS required for the live/hosted handoff --------------------------


def test_sso_initiation_rejects_http_tenant() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        response = _initiate_sso(
            client, challenge=challenge, tenant_url="http://acme.demo.resourcespace.local"
        )
        assert response.status_code == 400, response.text
        assert "TENANT_NOT_HTTPS" in response.text
        assert "location" not in {k.lower() for k in response.headers.keys()}


# --- 21. Malformed / oversized OAuth parameters are rejected -----------------


def test_sso_initiation_rejects_malformed_code_challenge() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        response = _initiate_sso(client, challenge="unused", code_challenge="too-short")
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
        # Nothing was persisted for a rejected initiation.
        assert _read_store(storage_path)["pendingSsoStates"] == {}


def test_sso_initiation_rejects_oversized_state() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        response = _initiate_sso(client, challenge=challenge, canva_state="x" * 600)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
        assert _read_store(storage_path)["pendingSsoStates"] == {}


# --- 22. Callback identity claims are not trusted -----------------------------


def test_sso_callback_ignores_spoofed_email_and_fullname() -> None:
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, verifier, redirect_uri = _run_full_sso_initiation(client)
        response = _sso_callback(
            client,
            handoff_state=handoff_state,
            fullname="Evil Attacker",
            email="attacker@example.com",
        )
        assert response.status_code == 200, response.text

        completion = urlparse(response.json()["redirectUrl"])
        code = parse_qs(completion.query)["code"][0]
        tokens = _exchange_code_for_tokens(client, code=code, verifier=verifier, redirect_uri=redirect_uri)

        userinfo = client.get(
            "/oauth/userinfo",
            headers={"authorization": f"Bearer {tokens['access_token']}"},
        )
        assert userinfo.status_code == 200, userinfo.text
        body = userinfo.json()
        assert body["name"] == "Alice Admin"
        assert "email" not in body


def test_sso_initiation_rejects_noncanonical_s256_challenge_length() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        response = _initiate_sso(
            client,
            challenge=challenge,
            code_challenge="A" * 44,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
        assert _read_store(storage_path)["pendingSsoStates"] == {}


def test_sso_initiation_rejects_invalid_s256_pad_bits() -> None:
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        response = _initiate_sso(
            client,
            challenge=challenge,
            code_challenge=("A" * 42) + "B",
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"
        assert _read_store(storage_path)["pendingSsoStates"] == {}


def test_sso_initiation_enforces_per_source_pending_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "resourcespace_platform.services.auth_service._max_pending_sso_states_per_source",
        lambda _config: 2,
    )
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        for index in range(2):
            response = _initiate_sso(client, challenge=challenge, canva_state=f"state-{index}")
            assert response.status_code == 302, response.text
        overflow = _initiate_sso(client, challenge=challenge, canva_state="state-overflow")
        assert overflow.status_code == 503, overflow.text
        assert overflow.json()["error"]["code"] == "SSO_CAPACITY"


def test_sso_initiation_global_cap_ignores_tombstones(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "resourcespace_platform.services.auth_service._MAX_PENDING_SSO_STATES",
        2,
    )
    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        for index in range(3):
            handoff_state, _, _ = _run_full_sso_initiation(
                client,
                canva_state=f"tombstone-{index}",
            )
            assert _sso_callback(client, handoff_state=handoff_state).status_code == 200

        store = _read_store(storage_path)
        assert len(store["pendingSsoStates"]) == 3
        assert all(record.get("usedAt") for record in store["pendingSsoStates"].values())

        response = _initiate_sso(client, challenge=challenge, canva_state="after-tombstones")
        assert response.status_code == 302, response.text


def test_sso_initiation_global_cap_counts_only_active_pending(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "resourcespace_platform.services.auth_service._MAX_PENDING_SSO_STATES",
        2,
    )
    for client, _ in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        _, challenge = _pkce_pair()
        for index in range(2):
            response = _initiate_sso(client, challenge=challenge, canva_state=f"active-{index}")
            assert response.status_code == 302, response.text
        overflow = _initiate_sso(client, challenge=challenge, canva_state="active-overflow")
        assert overflow.status_code == 503, overflow.text
        assert overflow.json()["error"]["code"] == "SSO_CAPACITY"


def test_sso_callback_concurrent_completion_mints_single_authorization_code() -> None:
    import threading

    for client, storage_path in _build_client(RESOURCE_SPACE_SSO_ENABLED="true"):
        handoff_state, _verifier, _redirect_uri = _run_full_sso_initiation(client)
        results: list[Any] = []
        barrier = threading.Barrier(2)

        def _post() -> None:
            barrier.wait()
            results.append(_sso_callback(client, handoff_state=handoff_state))

        threads = [threading.Thread(target=_post), threading.Thread(target=_post)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        status_codes = sorted(response.status_code for response in results)
        assert status_codes == [200, 400]
        assert sum(1 for response in results if response.json().get("reason") == "sso_state_replay") == 1

        store = _read_store(storage_path)
        assert len(store["authorizationCodes"]) == 1
        assert store["pendingSsoStates"][handoff_state]["usedAt"] is not None
