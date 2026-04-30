"""OAuth provider endpoints for the Canva integration.

- `GET /oauth/authorise`    — renders the popup sign-in form.
- `POST /oauth/authorise`   — consumes tenant URL + credentials, returns 302 with code.
- `POST /oauth/token`       — exchanges authorization_code or refresh_token.
- `POST /oauth/revoke`      — revokes an issued token.
- `GET /oauth/userinfo`     — returns user/tenant context for the bearer token.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import logger as log
from ..config import DEV_LIKE_ENVIRONMENTS, AppConfig
from ..http_utils import (
    cors_headers,
    error_envelope,
    json_error,
    read_bearer_token,
)
from pathlib import Path


router = APIRouter()


_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
)

_MANUAL_TEST_STATE = "manual-fixture-auth"
_MANUAL_TEST_VERIFIER = "manual-test-verifier-123456789"


def _sha256_b64url(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _manual_authorize_defaults(config: AppConfig) -> dict[str, str]:
    return {
        "client_id": config.oauth.client_id,
        "redirect_uri": f"{config.base_url.rstrip('/')}/oauth/manual/callback",
        "response_type": "code",
        "state": _MANUAL_TEST_STATE,
        "scope": "openid dam:read",
        "code_challenge": _sha256_b64url(_MANUAL_TEST_VERIFIER),
        "code_challenge_method": "S256",
    }


def _manual_test_mode_enabled(config: AppConfig) -> bool:
    """Manual OAuth helper is dev/test only — production deploys never expose it."""
    return config.environment in DEV_LIKE_ENVIRONMENTS


def _should_use_manual_test_mode(config: AppConfig, values: dict[str, str]) -> bool:
    if not _manual_test_mode_enabled(config):
        return False
    required_keys = ["client_id", "redirect_uri", "response_type", "state"]
    return not any(values.get(key) for key in required_keys)


def _is_redirect_uri_allowed(config: AppConfig, redirect_uri: str) -> bool:
    """Production deploys must enumerate redirect URIs Canva is configured to use.
    In dev/test the allowlist may be empty; we accept anything in that case so
    local fixtures and the manual helper still work."""
    allowlist = config.oauth.redirect_uri_allowlist
    if not allowlist:
        return _manual_test_mode_enabled(config)
    return redirect_uri in allowlist


def _render_authorize(
    config: AppConfig,
    query_params: dict[str, str],
    *,
    error_code: str | None = None,
    form_values: dict[str, str] | None = None,
    manual_test_mode: bool = False,
) -> str:
    hidden_keys = [
        "client_id",
        "redirect_uri",
        "response_type",
        "state",
        "scope",
        "code_challenge",
        "code_challenge_method",
    ]
    values = form_values or {}
    resolved_query_params = dict(query_params)
    if manual_test_mode:
        resolved_query_params = {**_manual_authorize_defaults(config), **resolved_query_params}
    hidden_fields = [(key, values.get(key) or resolved_query_params.get(key, "")) for key in hidden_keys]
    template = _ENV.get_template("authorize.html")
    return template.render(
        hidden_fields=hidden_fields,
        error_code=error_code,
        tenant_url=values.get("tenant_url", ""),
        username=values.get("username", ""),
        client_id=config.oauth.client_id,
        manual_test_mode=manual_test_mode,
    )


@router.get("/oauth/authorize")
async def oauth_authorize_legacy_get(request: Request) -> Response:
    query = urlencode(list(request.query_params.multi_items()))
    suffix = f"?{query}" if query else ""
    return RedirectResponse(
        status_code=307,
        url=f"/oauth/authorise{suffix}",
        headers=cors_headers(request.app.state.deps.config),
    )


@router.get("/oauth/authorise")
async def oauth_authorise_get(request: Request) -> Response:
    deps = request.app.state.deps
    query_params = dict(request.query_params)
    manual_test_mode = _should_use_manual_test_mode(deps.config, query_params)
    # The GET endpoint just renders the login form; Canva's OAuth-provider
    # flow is a browser navigation, not a server-to-server call, and Canva
    # does not attach `signatures`/`time`/`user`/`brand`/`extensions` query
    # parameters to it. The actual security boundary lives on the POST:
    # client_id is checked against config, redirect_uri against the
    # allowlist, and PKCE protects the subsequent code exchange.
    html = _render_authorize(
        deps.config,
        query_params,
        manual_test_mode=manual_test_mode,
    )
    return HTMLResponse(status_code=200, content=html, headers=cors_headers(deps.config))


@router.post("/oauth/authorize")
@router.post("/oauth/authorise")
async def oauth_authorize_post(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    rate = deps.rate_limiter.consume(
        f"oauth_authorize:{request.client.host if request.client else 'unknown'}"
    )
    if not rate.allowed:
        return json_error(
            config,
            429,
            "RATE_LIMITED",
            "Too many requests.",
            headers={"Retry-After": str(max(1, rate.retry_after_ms // 1000))},
        )

    form = await request.form()
    body: dict[str, str] = {key: str(form.get(key) or "") for key in form.keys()}
    manual_test_mode = _should_use_manual_test_mode(config, body)
    if manual_test_mode:
        for key, value in _manual_authorize_defaults(config).items():
            body.setdefault(key, value)

    client_id = body.get("client_id")
    redirect_uri = body.get("redirect_uri")
    response_type = body.get("response_type")
    state = body.get("state")
    scope = body.get("scope") or "openid dam:read"

    if response_type != "code" or not client_id or not redirect_uri or not state:
        return json_error(config, 400, "INVALID_REQUEST", "Missing OAuth parameters.")
    if client_id != config.oauth.client_id:
        return json_error(config, 400, "INVALID_CLIENT", "Unknown OAuth client_id.")
    if not _is_redirect_uri_allowed(config, redirect_uri):
        return json_error(
            config,
            400,
            "INVALID_REDIRECT_URI",
            "redirect_uri is not in OAUTH_REDIRECT_URI_ALLOWLIST.",
        )
    code_challenge_method = body.get("code_challenge_method") or "S256"
    if code_challenge_method != "S256":
        return json_error(
            config,
            400,
            "INVALID_REQUEST",
            "Only S256 PKCE is supported (code_challenge_method must be 'S256').",
        )

    try:
        code = deps.auth_service.begin_authorization(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=body.get("code_challenge"),
            code_challenge_method=code_challenge_method,
            tenant_base_url=body.get("tenant_url"),
            username=body.get("username", ""),
            password=body.get("password", ""),
        )
        log.info(
            "oauth_authorize_completed",
            {
                "clientId": client_id,
                "tenantUrl": body.get("tenant_url"),
                "username": body.get("username"),
            },
        )
        parsed = urlparse(redirect_uri)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        query_pairs.extend([("code", code), ("state", state)])
        target = parsed._replace(query=urlencode(query_pairs)).geturl()
        return RedirectResponse(status_code=302, url=target, headers=cors_headers(config))
    except Exception as exc:  # noqa: BLE001 — map all to the authorize page
        mapped = deps.resourcespace_service.map_error(exc)
        html = _render_authorize(
            config,
            dict(request.query_params),
            error_code=mapped.code,
            form_values=body,
            manual_test_mode=manual_test_mode,
        )
        return HTMLResponse(
            status_code=mapped.status_code or 400,
            content=html,
            headers=cors_headers(config),
        )


@router.get("/oauth/manual/callback")
async def oauth_manual_callback(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    # Hard-gate the manual helper. Production deploys (APP_ENV != development/test)
    # must never see this endpoint return tokens.
    if not _manual_test_mode_enabled(config):
        return json_error(config, 404, "NOT_FOUND", "Not found.")

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or state != _MANUAL_TEST_STATE:
        return json_error(
            config,
            400,
            "INVALID_REQUEST",
            "Missing or invalid manual callback parameters.",
        )

    payload = deps.auth_service.exchange_authorization_code(
        client_id=config.oauth.client_id,
        redirect_uri=_manual_authorize_defaults(config)["redirect_uri"],
        code=code,
        code_verifier=_MANUAL_TEST_VERIFIER,
    )
    if payload.get("error"):
        return JSONResponse(status_code=400, content=payload, headers=cors_headers(config))

    record = deps.auth_service.read_access_token(payload["access_token"])
    session_summary = (
        deps.resourcespace_service.get_session_summary(record["session"]) if record else None
    )
    return JSONResponse(
        status_code=200,
        content={
            "type": "SUCCESS",
            "message": "Manual OAuth flow completed.",
            "token": payload,
            "session": session_summary,
        },
        headers=cors_headers(config),
    )


@router.post("/oauth/token")
async def oauth_token(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    rate = deps.rate_limiter.consume(
        f"oauth_token:{request.client.host if request.client else 'unknown'}"
    )
    if not rate.allowed:
        return json_error(
            config,
            429,
            "RATE_LIMITED",
            "Too many requests.",
            headers={"Retry-After": str(max(1, rate.retry_after_ms // 1000))},
        )

    form = await request.form()
    body: dict[str, str] = {key: str(form.get(key) or "") for key in form.keys()}
    grant_type = body.get("grant_type")

    if grant_type == "authorization_code":
        payload = deps.auth_service.exchange_authorization_code(
            client_id=body.get("client_id", ""),
            redirect_uri=body.get("redirect_uri", ""),
            code=body.get("code", ""),
            code_verifier=body.get("code_verifier"),
        )
    elif grant_type == "refresh_token":
        payload = deps.auth_service.refresh_access_token(
            client_id=body.get("client_id", ""),
            refresh_token=body.get("refresh_token", ""),
        )
    else:
        payload = {"error": "unsupported_grant_type", "description": "Unsupported grant type."}

    if payload.get("error"):
        log.warn("oauth_token_failed", {"error": payload.get("error")})
        return JSONResponse(status_code=400, content=payload, headers=cors_headers(config))
    return JSONResponse(status_code=200, content=payload, headers=cors_headers(config))


@router.post("/oauth/revoke")
async def oauth_revoke(request: Request) -> Response:
    deps = request.app.state.deps
    form = await request.form()
    token = str(form.get("token") or "")
    deps.auth_service.revoke_token(token)
    return Response(status_code=200, content="", headers=cors_headers(deps.config))


@router.get("/oauth/userinfo")
async def oauth_userinfo(request: Request) -> Response:
    deps = request.app.state.deps
    token = read_bearer_token(request)
    if not token:
        return json_error(deps.config, 401, "UNAUTHORIZED", "Unauthorized.")
    payload = deps.auth_service.read_user_info_from_access_token(token)
    if not payload:
        return json_error(deps.config, 401, "UNAUTHORIZED", "Unauthorized.")
    return JSONResponse(status_code=200, content=payload, headers=cors_headers(deps.config))
