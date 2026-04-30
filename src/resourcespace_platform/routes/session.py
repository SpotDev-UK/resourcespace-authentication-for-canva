"""Session context endpoint backing the Canva app's bootstrap call."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ..http_utils import cors_headers, json_error, read_bearer_token


router = APIRouter()


@router.get("/api/session")
async def api_session(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config
    token = read_bearer_token(request)
    if not token:
        return json_error(config, 401, "MISSING_BEARER_TOKEN", "Missing bearer token.")
    record = deps.auth_service.read_access_token(token)
    if not record:
        return json_error(config, 401, "SESSION_EXPIRED", "Access token is invalid or expired.")

    summary = deps.resourcespace_service.get_session_summary(record["session"])
    return JSONResponse(
        status_code=200,
        content={
            "contractVersion": "1.0.0",
            "mode": summary["mode"],
            "tenant": summary["tenant"],
            "user": summary["user"],
        },
        headers=cors_headers(config),
    )
