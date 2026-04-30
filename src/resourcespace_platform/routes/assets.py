"""Signed-URL delivery endpoints for previews and downloads."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from ..http_utils import cors_headers, error_envelope


router = APIRouter()


async def _serve_grant(request: Request, grant_id: str) -> Response:
    deps = request.app.state.deps
    config = deps.config
    verification = deps.asset_service.verify_grant(
        grant_id=grant_id,
        expires_at=request.query_params.get("expires"),
        signature=request.query_params.get("sig"),
    )
    if not verification["ok"]:
        reason = verification["reason"]
        status = 410 if reason == "expired" else 403
        return JSONResponse(
            status_code=status,
            content=error_envelope(reason.upper(), reason),
            headers=cors_headers(config),
        )

    built = await deps.asset_service.build_grant_response(verification, cors_headers(config))
    if built is None:
        return JSONResponse(
            status_code=404,
            content=error_envelope("NOT_FOUND", "Not found."),
            headers=cors_headers(config),
        )

    status_code, body, headers = built
    return Response(status_code=status_code, content=body, headers=headers)


@router.get("/public/assets/{grant_id}")
async def public_assets(grant_id: str, request: Request) -> Response:
    return await _serve_grant(request, grant_id)


@router.get("/signed/assets/{grant_id}")
async def signed_assets(grant_id: str, request: Request) -> Response:
    return await _serve_grant(request, grant_id)
