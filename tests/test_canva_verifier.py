"""Canva request-signature verification tests.

Mirrors the Node `canva-request-verifier.test.js` suite.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from urllib.parse import urlencode

from resourcespace_platform.config import create_config
from resourcespace_platform.services.canva_verifier import (
    verify_canva_get_request,
    verify_canva_post_request,
)


def _sign(secret: bytes, message: str) -> str:
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def _make_config(client_secret_b64: str) -> object:
    return create_config(
        {
            "CANVA_CLIENT_SECRET": client_secret_b64,
            "CANVA_REQUEST_VERIFICATION_MODE": "required",
            "CANVA_REQUEST_TIMESTAMP_TOLERANCE_SECONDS": "300",
        }
    )


def test_verify_canva_get_request_accepts_valid_signed_oauth_requests() -> None:
    client_secret_b64 = base64.b64encode(b"signed-get-secret").decode("ascii")
    secret = base64.b64decode(client_secret_b64)
    time_value = str(int(time.time()))
    message = f"v1:{time_value}:user_123:brand_456:design_editor:opaque-state"
    signature = _sign(secret, message)

    query_params = {
        "time": time_value,
        "user": "user_123",
        "brand": "brand_456",
        "extensions": "design_editor",
        "state": "opaque-state",
        "signatures": signature,
    }

    result = verify_canva_get_request(
        config=_make_config(client_secret_b64),
        query_params=query_params,
    )
    assert result.ok is True
    assert result.reason is None


def test_verify_canva_post_request_accepts_valid_and_rejects_tampered() -> None:
    client_secret_b64 = base64.b64encode(b"signed-post-secret").decode("ascii")
    secret = base64.b64decode(client_secret_b64)
    raw_body = json.dumps({"user_id": "user_alice", "tenant_id": "tenant_acme"})
    timestamp = str(int(time.time()))
    path = "/webhooks/canva/user-uninstall"
    signature = _sign(secret, f"v1:{timestamp}:{path}:{raw_body}")

    headers = {
        "x-canva-timestamp": timestamp,
        "x-canva-signatures": signature,
    }

    accepted = verify_canva_post_request(
        config=_make_config(client_secret_b64),
        headers=headers,
        path=path,
        raw_body=raw_body,
    )
    assert accepted.ok is True

    tampered = verify_canva_post_request(
        config=_make_config(client_secret_b64),
        headers=headers,
        path=path,
        raw_body=json.dumps({"user_id": "user_alice", "tenant_id": "tenant_globex"}),
    )
    assert tampered.ok is False
    assert tampered.reason == "invalid_signature"
