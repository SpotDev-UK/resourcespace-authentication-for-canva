"""Shared HTTP helpers — CORS headers, error envelopes, bearer parsing, continuation cursors."""
from __future__ import annotations

import base64
import json
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from .config import AppConfig


CANVA_SIGNATURE_HEADERS = "authorization, content-type, x-canva-signatures, x-canva-timestamp"


def cors_headers(config: AppConfig, extra: dict[str, str] | None = None) -> dict[str, str]:
    """Return CORS-related response headers.

    `Access-Control-Allow-Origin` is intentionally left to the FastAPI
    `CORSMiddleware` so it can echo whichever entry of the (comma-separated)
    ``CORS_ORIGIN`` config matches the current request. Writing it manually
    here would either pin to one entry (wrong for multi-origin setups) or
    be overwritten by the middleware anyway.
    """
    headers = {
        "Access-Control-Allow-Headers": CANVA_SIGNATURE_HEADERS,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    }
    if extra:
        headers.update(extra)
    return headers


def error_envelope(code: str, message: str, details: Any | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        payload["error"]["details"] = details
    return payload


def json_error(
    config: AppConfig,
    status_code: int,
    code: str,
    message: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    merged = cors_headers(config, headers)
    return JSONResponse(
        status_code=status_code,
        content=error_envelope(code, message),
        headers=merged,
    )


def read_bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization") or ""
    if not header.startswith("Bearer "):
        return None
    return header[len("Bearer ") :]


def token_has_scope(record: dict[str, Any], required_scope: str) -> bool:
    """Return True when the access-token record includes ``required_scope``."""
    granted = (record or {}).get("scope") or ""
    return required_scope in granted.split()


def encode_continuation(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_continuation(value: str | None) -> dict[str, Any] | None:
    if not value:
        return {"containerOffset": 0, "assetOffset": 0, "scopeKey": None}
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(value + padding)
        parsed = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    return {
        "containerOffset": int(parsed.get("containerOffset") or 0),
        "assetOffset": int(parsed.get("assetOffset") or 0),
        "scopeKey": parsed.get("scopeKey"),
    }


def scope_key(
    *,
    container_id: str | None,
    query: str,
    sort: str,
    types: list[str],
) -> str:
    return json.dumps(
        {
            "containerId": container_id,
            "query": query,
            "sort": sort,
            "types": types,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def client_host(request: Request) -> str:
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
