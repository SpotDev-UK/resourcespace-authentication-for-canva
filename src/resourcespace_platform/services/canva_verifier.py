"""Canva request-signature verification.

Canva signs inbound OAuth GET requests via `signatures`, `time`, `user`, `brand`,
`extensions`, and `state` query parameters, and signs inbound POST requests with
`x-canva-signatures` and `x-canva-timestamp` headers.

The client secret is base64-encoded; we decode it once per call.
"""
from __future__ import annotations

import base64
import hmac
import time
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping

from ..config import AppConfig


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str | None = None
    skipped: bool = False

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"ok": self.ok}
        if self.reason is not None:
            payload["reason"] = self.reason
        if self.skipped:
            payload["skipped"] = True
        return payload


def _split_signatures(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [value.strip() for value in raw.split(",") if value.strip()]


def _is_valid_timestamp(sent: int, received: int, leniency: int) -> bool:
    return abs(sent - received) < leniency


def _calculate_signature(secret: bytes, message: str) -> str:
    return hmac.new(secret, message.encode("utf-8"), sha256).hexdigest()


def _should_verify(mode: str, marker_present: bool) -> bool:
    if mode == "off":
        return False
    if mode == "required":
        return True
    # "smart" (development convenience): only verify when Canva actually
    # supplied signature material. Production deploys must use "required";
    # `validate_config_for_environment` enforces that at startup.
    return marker_present


def _decode_secret(config: AppConfig) -> bytes | None:
    secret = config.signing.canva_client_secret
    if not secret:
        return None
    try:
        return base64.b64decode(secret)
    except (ValueError, TypeError):
        return None


def verify_canva_get_request(
    *, config: AppConfig, query_params: Mapping[str, str]
) -> VerificationResult:
    signatures = _split_signatures(query_params.get("signatures"))
    should_run = _should_verify(config.signing.request_verification_mode, bool(signatures))
    if not should_run:
        return VerificationResult(ok=True, skipped=True)

    secret = _decode_secret(config)
    if secret is None:
        return VerificationResult(ok=False, reason="missing_client_secret")

    time_value = query_params.get("time")
    user = query_params.get("user")
    brand = query_params.get("brand")
    extensions = query_params.get("extensions")
    state = query_params.get("state")

    if not all([time_value, user, brand, extensions, state, signatures]):
        return VerificationResult(ok=False, reason="missing_signature_fields")

    try:
        sent = int(time_value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return VerificationResult(ok=False, reason="invalid_timestamp")

    if not _is_valid_timestamp(
        sent,
        int(time.time()),
        config.signing.request_timestamp_tolerance_seconds,
    ):
        return VerificationResult(ok=False, reason="invalid_timestamp")

    message = f"v1:{time_value}:{user}:{brand}:{extensions}:{state}"
    expected = _calculate_signature(secret, message)
    if expected not in signatures:
        return VerificationResult(ok=False, reason="invalid_signature")

    return VerificationResult(ok=True)


def verify_canva_post_request(
    *,
    config: AppConfig,
    headers: Mapping[str, str],
    path: str,
    raw_body: str,
) -> VerificationResult:
    signatures = _split_signatures(headers.get("x-canva-signatures"))
    timestamp = headers.get("x-canva-timestamp")
    should_run = _should_verify(config.signing.request_verification_mode, bool(signatures))
    if not should_run:
        return VerificationResult(ok=True, skipped=True)

    secret = _decode_secret(config)
    if secret is None:
        return VerificationResult(ok=False, reason="missing_client_secret")

    if not timestamp or not signatures:
        return VerificationResult(ok=False, reason="missing_signature_fields")

    try:
        sent = int(timestamp)
    except (TypeError, ValueError):
        return VerificationResult(ok=False, reason="invalid_timestamp")

    if not _is_valid_timestamp(
        sent,
        int(time.time()),
        config.signing.request_timestamp_tolerance_seconds,
    ):
        return VerificationResult(ok=False, reason="invalid_timestamp")

    message = f"v1:{timestamp}:{path}:{raw_body}"
    expected = _calculate_signature(secret, message)
    if expected not in signatures:
        return VerificationResult(ok=False, reason="invalid_signature")

    return VerificationResult(ok=True)
