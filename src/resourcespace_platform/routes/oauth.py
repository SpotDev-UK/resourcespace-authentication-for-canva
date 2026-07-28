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
import re
import secrets
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import logger as log
from ..config import DEV_LIKE_ENVIRONMENTS, AppConfig
from ..http_utils import (
    client_host,
    cors_headers,
    error_envelope,
    json_error,
    read_bearer_token,
    resolve_client_host,
)
from ..services.resourcespace import ResourceSpaceError, get_configured_tenant
from pathlib import Path


router = APIRouter()


_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
)

_MANUAL_TEST_STATE = "manual-fixture-auth"
_MANUAL_TEST_VERIFIER = "manual-test-verifier-123456789"

# Bounds on caller-controlled OAuth parameters. These values are persisted (in
# pending SSO state before any authentication, and in auth codes after), so
# unbounded input is a store-exhaustion vector on the unauthenticated SSO
# initiation path.
_MAX_STATE_LEN = 512
_MAX_SCOPE_LEN = 256
_MAX_CODE_CHALLENGE_LEN = 128
_MAX_TENANT_URL_LEN = 2048
# A PKCE S256 challenge is base64url of a SHA-256 digest: exactly 43 chars.
_CODE_CHALLENGE_RE = re.compile(r"\A[A-Za-z0-9_-]{43}\Z")


def _is_valid_s256_code_challenge(challenge: str) -> bool:
    if not _CODE_CHALLENGE_RE.match(challenge):
        return False
    try:
        padding = "=" * (-len(challenge) % 4)
        digest = base64.urlsafe_b64decode(challenge + padding)
    except ValueError:
        return False
    if len(digest) != 32:
        return False
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii") == challenge


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


def _is_oauth_client_allowed(config: AppConfig, client_id: str) -> bool:
    return client_id in config.oauth.clients


def _is_redirect_uri_allowed(config: AppConfig, client_id: str, redirect_uri: str) -> bool:
    """Production deploys must enumerate redirect URIs Canva is configured to use.
    In dev/test the allowlist may be empty; we accept anything in that case so
    local fixtures and the manual helper still work."""
    client = config.oauth.clients.get(client_id)
    if not client:
        return False
    allowlist = client.redirect_uri_allowlist
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
        sso_enabled=config.resource_space.sso_enabled,
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

    rate = deps.rate_limiter.consume(f"oauth_authorize:{client_host(request, deps.config)}")
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
    if not _is_oauth_client_allowed(config, client_id):
        return json_error(config, 400, "INVALID_CLIENT", "Unknown OAuth client_id.")
    if not _is_redirect_uri_allowed(config, client_id, redirect_uri):
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

    # Bound the sizes of caller-controlled OAuth parameters before anything is
    # persisted (see the length constants above).
    if (
        len(state) > _MAX_STATE_LEN
        or len(scope) > _MAX_SCOPE_LEN
        or len(body.get("code_challenge") or "") > _MAX_CODE_CHALLENGE_LEN
        or len(body.get("tenant_url") or "") > _MAX_TENANT_URL_LEN
    ):
        return json_error(
            config, 400, "INVALID_REQUEST", "OAuth request parameters exceed length limits."
        )

    code_challenge = body.get("code_challenge")
    if not code_challenge or not _is_valid_s256_code_challenge(code_challenge):
        return json_error(
            config,
            400,
            "INVALID_REQUEST",
            "A valid S256 code_challenge is required.",
        )

    # Branch on the auth method only after the shared OAuth-request validation
    # above (client/redirect allowlist + PKCE). `password` is the default.
    if (body.get("auth_method") or "password").strip().lower() == "sso":
        return _begin_sso_authorize(
            request,
            body=body,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

    try:
        code = deps.auth_service.begin_authorization(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            tenant_base_url=body.get("tenant_url"),
            username=body.get("username", ""),
            password=body.get("password", ""),
        )
        # Log the tenant host only. The raw username (often an email address)
        # and the full tenant URL are PII and must not be logged.
        raw_tenant = body.get("tenant_url") or ""
        parsed_tenant = urlparse(raw_tenant if "://" in raw_tenant else f"//{raw_tenant}")
        log.info(
            "oauth_authorize_completed",
            {
                "clientId": client_id,
                "tenantHost": (parsed_tenant.hostname or "").lower(),
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


def _host_of(url: str | None) -> str:
    return (urlparse(url or "").hostname or "").lower()


def _sso_headers(config: AppConfig) -> dict[str, str]:
    # Responses that carry the handoff/Canva state or an authorization code in
    # their URL must not leak it via Referer to third-party subresources, nor be
    # cached by shared proxies.
    return {
        **cors_headers(config),
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }


def _append_query(url: str, params: list[tuple[str, str]]) -> str:
    parsed = urlparse(url)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_pairs.extend(params)
    return parsed._replace(query=urlencode(query_pairs)).geturl()


def _sso_json(
    config: AppConfig,
    status_code: int,
    message: str,
    *,
    reason: str | None = None,
    redirect_url: str | None = None,
) -> Response:
    """Build the callback response.

    ResourceSpace calls this endpoint server-side, treats only HTTP 200 from the
    broker as success, and reads the JSON body. The broker always returns JSON
    (never a 3xx). ``reason`` is a machine-readable failure class for our
    logs/tests (RS reads only ``message`` and ignores it). On success,
    ``redirectUrl`` carries the Canva completion URL (redirect_uri + code +
    state). With Dan's ResourceSpace SSO patch applied, ResourceSpace issues an
    HTTP 303 to that URL so the browser popup completes the handoff.
    """
    payload: dict[str, Any] = {"message": message}
    if reason:
        payload["reason"] = reason
    if redirect_url:
        payload["redirectUrl"] = redirect_url
    # Use _sso_headers (Cache-Control: no-store, Referrer-Policy: no-referrer):
    # a success response carries a fresh authorization code in redirectUrl and
    # must not be cached by any intermediary.
    return JSONResponse(status_code=status_code, content=payload, headers=_sso_headers(config))


def _begin_sso_authorize(
    request: Request,
    *,
    body: dict[str, str],
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str,
) -> Response:
    deps = request.app.state.deps
    config = deps.config

    if not config.resource_space.sso_enabled:
        html = _render_authorize(
            config,
            dict(request.query_params),
            error_code="SSO_DISABLED",
            form_values=body,
        )
        return HTMLResponse(status_code=400, content=html, headers=cors_headers(config))

    # Preserve the established SSO error contract before tenant resolution.
    # The production resolver also rejects plaintext dynamic tenants, but doing
    # this here keeps the user-facing failure specific and ensures no handoff
    # state is ever created for an explicit HTTP URL.
    requested_tenant_url = (body.get("tenant_url") or "").strip()
    if urlparse(requested_tenant_url).scheme.lower() == "http":
        html = _render_authorize(
            config,
            dict(request.query_params),
            error_code="TENANT_NOT_HTTPS",
            form_values=body,
        )
        return HTMLResponse(status_code=400, content=html, headers=cors_headers(config))

    try:
        tenant = get_configured_tenant(config, requested_tenant_url)
    except Exception as exc:  # noqa: BLE001 (map to the authorize page)
        mapped = deps.resourcespace_service.map_error(exc)
        html = _render_authorize(
            config,
            dict(request.query_params),
            error_code=mapped.code,
            form_values=body,
        )
        return HTMLResponse(
            status_code=mapped.status_code or 400,
            content=html,
            headers=cors_headers(config),
        )

    # Require HTTPS for the hosted-login handoff: the browser is redirected to
    # this tenant carrying the handoff state, so a plaintext tenant would expose
    # the login page and state to network interception.
    if not str(tenant.get("baseUrl", "")).lower().startswith("https://"):
        html = _render_authorize(
            config,
            dict(request.query_params),
            error_code="TENANT_NOT_HTTPS",
            form_values=body,
        )
        return HTMLResponse(status_code=400, content=html, headers=cors_headers(config))

    correlation_id = secrets.token_urlsafe(12)
    client_resolution = resolve_client_host(request, config)
    try:
        initiator_key = f"oauth_sso_init:{client_resolution.host}"
        handoff_state = deps.auth_service.begin_sso_authorization(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            canva_state=state,
            tenant=tenant,
            correlation_id=correlation_id,
            initiator_key=initiator_key,
        )
    except ResourceSpaceError as exc:
        # Pending-state capacity exhausted (flood protection).
        return json_error(config, exc.status_code or 503, exc.code, exc.message)
    log.info(
        "oauth_sso_initiated",
        {
            "correlationId": correlation_id,
            "clientId": client_id,
            "tenantHost": _host_of(tenant.get("baseUrl")),
            **client_resolution.log_context(config=config),
        },
    )
    query = urlencode(
        {"system": config.resource_space.sso_system_key, "state": handoff_state}
    )
    target = f"{tenant['baseUrl'].rstrip('/')}/pages/user/user_api_session.php?{query}"
    return RedirectResponse(status_code=302, url=target, headers=_sso_headers(config))


@router.post("/oauth/sso/callback")
async def oauth_sso_callback(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    # Hard-gate on the SSO flag: while disabled, the unauthenticated,
    # upstream-triggering endpoint is invisible (matches the manual-callback
    # gating idiom).
    if not config.resource_space.sso_enabled:
        return json_error(config, 404, "NOT_FOUND", "Not found.")

    correlation_id = secrets.token_urlsafe(12)
    client_resolution = resolve_client_host(request, config)
    log.info(
        "oauth_sso_callback_received",
        {
            "correlationId": correlation_id,
            **client_resolution.log_context(config=config),
        },
    )

    rate = deps.rate_limiter.consume(f"oauth_sso_callback:{client_resolution.host}")
    if not rate.allowed:
        return json_error(
            config,
            429,
            "RATE_LIMITED",
            "Too many requests.",
            headers={"Retry-After": str(max(1, rate.retry_after_ms // 1000))},
        )

    form = await request.form()
    handoff_state = str(form.get("state") or "")
    session_key = str(form.get("sessionkey") or "")
    username = str(form.get("username") or "")

    if not handoff_state:
        log.info(
            "oauth_sso_state_invalid",
            {"correlationId": correlation_id, "reason": "missing_state"},
        )
        return _sso_json(
            config, 400,
            "This sign-in link is not valid. Please start again from Canva.",
            reason="sso_state_invalid",
        )

    consumed = deps.auth_service.inspect_pending_sso_state(handoff_state)
    status = consumed["status"]
    if status == "invalid":
        log.info(
            "oauth_sso_state_invalid",
            {"correlationId": correlation_id, "reason": "unknown_state"},
        )
        return _sso_json(
            config, 400,
            "This sign-in link is not valid. Please start again from Canva.",
            reason="sso_state_invalid",
        )

    record = consumed["record"]
    correlation_id = record.get("correlationId") or correlation_id
    if status == "expired":
        log.info("oauth_sso_state_expired", {"correlationId": correlation_id})
        return _sso_json(
            config, 400,
            "This sign-in link has expired. Please start again from Canva.",
            reason="sso_state_expired",
        )
    if status == "replayed":
        log.info("oauth_sso_state_replay", {"correlationId": correlation_id})
        return _sso_json(
            config, 400,
            "This sign-in link has already been used. Please start again from Canva.",
            reason="sso_state_replay",
        )

    if status != "active":
        # Defensive: inspect only returns invalid/expired/replayed/active.
        log.info(
            "oauth_sso_state_invalid",
            {"correlationId": correlation_id, "reason": "unexpected_state"},
        )
        return _sso_json(
            config, 400,
            "This sign-in link is not valid. Please start again from Canva.",
            reason="sso_state_invalid",
        )

    record = consumed["record"]
    tenant = record["tenant"]
    client_id = record["clientId"]
    redirect_uri = record["redirectUri"]
    canva_state = record["canvaState"]
    tenant_host = _host_of(tenant.get("baseUrl"))
    client_cfg = config.oauth.clients.get(client_id)
    integration = client_cfg.integration if client_cfg else None

    # Missing username never reaches upstream: the signed RS call keys identity
    # off `user`, so a blank username can never validate and must not be invented.
    if not username:
        log.info(
            "oauth_sso_handoff_failed",
            {"correlationId": correlation_id, "reason": "missing_username"},
        )
        return _sso_json(
            config, 400,
            "ResourceSpace did not provide a username for this sign-in.",
            reason="sso_handoff_failed",
        )

    if not session_key:
        log.info(
            "oauth_sso_token_validation_failed",
            {"correlationId": correlation_id, "clientId": client_id,
             "tenantHost": tenant_host, "reason": "missing_sessionkey"},
        )
        return _sso_json(
            config, 401,
            "ResourceSpace did not provide a valid session.",
            reason="resourcespace_token_validation_failed",
        )

    try:
        session = deps.resourcespace_service.authenticate_with_session_key(
            tenant=tenant,
            session_key=session_key,
            username=username,
            integration=integration,
        )
    except ResourceSpaceError as exc:
        mapped = deps.resourcespace_service.map_error(exc)
        # 401 for invalid/expired session key; 502 for upstream/connectivity.
        status_code = 401 if mapped.status_code in (400, 401, 403) else 502
        log.info(
            "oauth_sso_token_validation_failed",
            {"correlationId": correlation_id, "clientId": client_id,
             "tenantHost": tenant_host, "reason": mapped.code},
        )
        return _sso_json(
            config, status_code,
            "ResourceSpace session validation failed.",
            reason="resourcespace_token_validation_failed",
        )

    completed = deps.auth_service.complete_sso_authorization(
        handoff_state,
        session=session,
    )
    completion_status = completed["status"]
    if completion_status == "replayed":
        log.info("oauth_sso_state_replay", {"correlationId": correlation_id})
        return _sso_json(
            config, 400,
            "This sign-in link has already been used. Please start again from Canva.",
            reason="sso_state_replay",
        )
    if completion_status != "valid":
        log.info(
            "oauth_sso_state_invalid",
            {"correlationId": correlation_id, "reason": completion_status},
        )
        return _sso_json(
            config, 400,
            "This sign-in link is not valid. Please start again from Canva.",
            reason="sso_state_invalid",
        )

    code = completed["code"]
    # The authorization code is minted and bound to the Canva request. ResourceSpace
    # reads redirectUrl from this JSON response and (with the SSO redirect patch)
    # sends the browser popup to that URL via HTTP 303.
    completion_url = _append_query(redirect_uri, [("code", code), ("state", canva_state)])
    log.info(
        "oauth_sso_token_validation_succeeded",
        {"correlationId": correlation_id, "clientId": client_id, "tenantHost": tenant_host},
    )
    log.info(
        "oauth_sso_callback_completed",
        {"correlationId": correlation_id, "clientId": client_id,
         "tenantHost": tenant_host, "usernameProvided": bool(username)},
    )
    return _sso_json(
        config, 200,
        "Signed in to ResourceSpace. You can return to Canva to continue.",
        redirect_url=completion_url,
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

    rate = deps.rate_limiter.consume(f"oauth_token:{client_host(request, deps.config)}")
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
