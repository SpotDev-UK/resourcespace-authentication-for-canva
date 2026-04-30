"""Canva app lifecycle webhooks."""
from __future__ import annotations

import json

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .. import logger as log
from ..http_utils import cors_headers, error_envelope, json_error
from ..services.canva_verifier import verify_canva_post_request


router = APIRouter()


@router.post("/webhooks/canva/user-uninstall")
async def canva_user_uninstall(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    raw_body = (await request.body()).decode("utf-8")
    verification = verify_canva_post_request(
        config=config,
        headers={key.lower(): value for key, value in request.headers.items()},
        path=request.url.path,
        raw_body=raw_body,
    )
    if not verification.ok:
        log.warn(
            "canva_signature_rejected",
            {"path": request.url.path, "reason": verification.reason},
        )
        return json_error(
            config,
            401,
            "INVALID_CANVA_SIGNATURE",
            "The Canva request signature was invalid.",
        )

    try:
        body = json.loads(raw_body) if raw_body else {}
        user_id = body.get("user_id")
        tenant_id = body.get("tenant_id")
        if user_id and tenant_id:
            deps.auth_service.revoke_tokens_for_user(user_id=user_id, tenant_id=tenant_id)
            log.info("canva_user_uninstall", {"userId": user_id, "tenantId": tenant_id})
        return JSONResponse(
            status_code=200,
            content={"type": "SUCCESS"},
            headers=cors_headers(config),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        log.error("canva_user_uninstall_failed", {"error": str(exc)})
        return JSONResponse(
            status_code=400,
            content=error_envelope("INVALID_REQUEST", "Invalid uninstall payload."),
            headers=cors_headers(config),
        )
