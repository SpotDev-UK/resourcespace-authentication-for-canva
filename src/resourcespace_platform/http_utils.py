"""Shared HTTP helpers — CORS headers, error envelopes, bearer parsing, continuation cursors."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from .config import AppConfig
from .trusted_proxy import client_ip_from_x_forwarded_for, host_matches_trusted_proxy


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


def _client_ip_log_key(config: AppConfig | None) -> str:
    if config is None:
        return "development-client-ip-log-key"
    if config.client_ip_log_key:
        return config.client_ip_log_key
    return config.signing.asset_secret or "development-client-ip-log-key"


def pseudonymize_client_ip(value: str, key: str) -> str | None:
    """Return a keyed HMAC digest for log comparison (pseudonymization, not anonymization)."""
    if not value or value == "unknown":
        return None
    return hmac.new(key.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:12]


@dataclass(frozen=True)
class ClientHostResolution:
    host: str
    transport_peer: str
    client_ip_header: str
    header_trusted: bool
    header_present: bool

    def log_context(self, *, config: AppConfig | None = None) -> dict[str, Any]:
        log_key = _client_ip_log_key(config)
        context: dict[str, Any] = {
            "transportPeerHash": pseudonymize_client_ip(self.transport_peer, log_key),
            "resolvedClientHostHash": pseudonymize_client_ip(self.host, log_key),
            "clientIpHeader": self.client_ip_header or None,
            "clientIpHeaderTrusted": self.header_trusted,
            "clientIpHeaderPresent": self.header_present,
        }
        if config and config.client_ip_log_diagnostics:
            context["transportPeer"] = self.transport_peer or None
        return context


def resolve_client_host(request: Request, config: AppConfig | None = None) -> ClientHostResolution:
    """Resolve the client address and diagnostics for rate limiting/logging."""
    resolved_config = config
    if resolved_config is None:
        app = getattr(request, "app", None)
        deps = getattr(app.state, "deps", None) if app is not None else None
        resolved_config = getattr(deps, "config", None) if deps is not None else None

    peer = request.client.host if request.client and request.client.host else ""
    header_name = resolved_config.client_ip_header if resolved_config else ""
    trusted_proxies = resolved_config.trusted_proxy_hosts if resolved_config else []
    raw_header = request.headers.get(header_name, "").strip() if header_name else ""
    header_present = bool(raw_header)
    header_trusted = bool(
        header_name and peer and host_matches_trusted_proxy(peer, trusted_proxies)
    )

    if header_trusted and header_present:
        if header_name == "x-forwarded-for":
            resolved = client_ip_from_x_forwarded_for(raw_header, trusted_proxies)
            if resolved:
                return ClientHostResolution(
                    host=resolved,
                    transport_peer=peer,
                    client_ip_header=header_name,
                    header_trusted=True,
                    header_present=True,
                )
        else:
            return ClientHostResolution(
                host=raw_header,
                transport_peer=peer,
                client_ip_header=header_name,
                header_trusted=True,
                header_present=True,
            )

    host = peer or "unknown"
    return ClientHostResolution(
        host=host,
        transport_peer=peer,
        client_ip_header=header_name,
        header_trusted=header_trusted,
        header_present=header_present,
    )


def client_host(request: Request, config: AppConfig | None = None) -> str:
    """Return the client address used for rate limiting and SSO quotas.

    ``CLIENT_IP_HEADER`` is honoured only when the transport peer matches
    ``TRUSTED_PROXY_HOSTS``. Direct connections always use the peer address
    so clients cannot spoof their identity via forwarding headers. For
    ``x-forwarded-for``, the rightmost untrusted hop is used so appended
    proxy chains cannot be bypassed by a client-controlled leftmost value.
    """
    return resolve_client_host(request, config).host
