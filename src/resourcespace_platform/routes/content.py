"""Canva-facing content endpoints: resource find + download-url grant issuance."""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .. import logger as log
from ..http_utils import (
    cors_headers,
    decode_continuation,
    encode_continuation,
    error_envelope,
    json_error,
    read_bearer_token,
    scope_key,
    token_has_scope,
)
from ..services.resourcespace import ResourceSpaceError


router = APIRouter()


def _build_image_response(asset: dict[str, Any], preview_grant: dict[str, Any]) -> dict[str, Any]:
    thumbnail_source = asset.get("thumbnailSource") or {}
    preview_source = asset.get("previewSource") or {}
    return {
        "id": asset["id"],
        "type": "IMAGE",
        "name": asset.get("name"),
        "description": asset.get("description"),
        "mimeType": asset.get("mimeType"),
        "filename": asset.get("filename"),
        "width": asset.get("width"),
        "height": asset.get("height"),
        "createdAt": asset.get("createdAt"),
        "updatedAt": asset.get("updatedAt"),
        "thumbnail": {
            "url": preview_grant["url"],
            "width": thumbnail_source.get("width"),
            "height": thumbnail_source.get("height"),
        },
        "dragAndDropPreview": {
            "url": preview_grant["url"],
            "width": preview_source.get("width") or asset.get("width"),
            "height": preview_source.get("height") or asset.get("height"),
        },
        "downloadPath": f"/content/resources/{asset['id']}/download-url",
    }


def _advance_asset_offset(current: int, page: dict[str, Any], total: int) -> int:
    scanned = page.get("scanned")
    consumed = max(0, int(scanned)) if scanned is not None else len(page.get("items") or [])
    if consumed <= 0:
        return max(current, total)
    return current + consumed


def _map_find_error(error: ResourceSpaceError) -> dict[str, str]:
    code = error.code
    if code == "UPSTREAM_SESSION_EXPIRED":
        return {"type": "ERROR", "errorCode": "CONFIGURATION_REQUIRED"}
    if code in ("FORBIDDEN", "UNKNOWN_TENANT"):
        return {"type": "ERROR", "errorCode": "FORBIDDEN"}
    if code == "NOT_FOUND":
        return {"type": "ERROR", "errorCode": "NOT_FOUND"}
    if code == "INVALID_TENANT_URL":
        return {"type": "ERROR", "errorCode": "INVALID_REQUEST"}
    if code == "UPSTREAM_UNAVAILABLE":
        return {"type": "ERROR", "errorCode": "TIMEOUT"}
    return {"type": "ERROR", "errorCode": "INTERNAL_ERROR"}


async def _raw_body(request: Request) -> str:
    cached = getattr(request.state, "raw_body", None)
    if cached is not None:
        return cached
    body = (await request.body()).decode("utf-8")
    request.state.raw_body = body
    return body


@router.post("/content/resources/find")
async def content_resources_find(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    rate = deps.rate_limiter.consume(
        f"content_find:{request.client.host if request.client else 'unknown'}"
    )
    if not rate.allowed:
        return json_error(
            config,
            429,
            "RATE_LIMITED",
            "Too many requests.",
            headers={"Retry-After": str(max(1, rate.retry_after_ms // 1000))},
        )

    raw_body = await _raw_body(request)
    # Note: /content/* endpoints are called as browser-direct fetches from
    # the Canva app origin (CORS preflight visible in access logs). The
    # browser can't add the `x-canva-signatures` header — only Canva's
    # server can, and only for server-to-server traffic like webhooks.
    # Bearer-token auth + scope enforcement + the CORS origin lock are the
    # actual security controls here. Signature verification is preserved
    # for genuinely server-to-server endpoints (see routes/webhooks.py).

    token = read_bearer_token(request)
    if not token:
        log.warn("auth_rejected", {"path": request.url.path, "reason": "missing_bearer_token"})
        return json_error(config, 401, "MISSING_BEARER_TOKEN", "Missing bearer token.")
    record = deps.auth_service.read_access_token(token)
    if not record:
        log.warn("auth_rejected", {"path": request.url.path, "reason": "session_expired"})
        return json_error(config, 401, "SESSION_EXPIRED", "Access token is invalid or expired.")
    if not token_has_scope(record, "dam:read"):
        log.warn("auth_rejected", {"path": request.url.path, "reason": "insufficient_scope", "required": "dam:read"})
        return json_error(config, 403, "INSUFFICIENT_SCOPE", "Token is missing the dam:read scope.")

    session = record["session"]

    body: dict[str, Any] = json.loads(raw_body) if raw_body else {}
    continuation_payload = decode_continuation(body.get("continuation"))
    if continuation_payload is None:
        return JSONResponse(
            status_code=400,
            content={"type": "ERROR", "errorCode": "INVALID_REQUEST"},
            headers=cors_headers(config),
        )

    types = body.get("types") or ["IMAGE", "CONTAINER"]
    query = body.get("query") or ""
    sort = body.get("sort") or "updated_desc"
    container_id = body.get("containerId")
    limit = int(body.get("limit") or 50)

    current_scope = scope_key(
        container_id=container_id,
        query=query,
        sort=sort,
        types=types,
    )
    if continuation_payload.get("scopeKey") and continuation_payload["scopeKey"] != current_scope:
        return JSONResponse(
            status_code=400,
            content={"type": "ERROR", "errorCode": "INVALID_REQUEST"},
            headers=cors_headers(config),
        )

    try:
        includes_containers = "CONTAINER" in types
        includes_images = "IMAGE" in types

        if includes_containers:
            if query:
                containers = deps.resourcespace_service.search_containers(session, container_id, query)
            else:
                containers = deps.resourcespace_service.list_containers(session, container_id)
        else:
            containers = []

        remaining = limit
        resources: list[dict[str, Any]] = []
        next_container_offset = continuation_payload["containerOffset"]
        sliced_containers = containers[next_container_offset : next_container_offset + remaining]
        resources.extend(sliced_containers)
        remaining -= len(sliced_containers)

        asset_offset = continuation_payload["assetOffset"]
        asset_total = 0

        if includes_images and remaining > 0:
            assets = deps.resourcespace_service.list_assets(
                session,
                query=query,
                container_id=container_id,
                offset=asset_offset,
                limit=remaining,
                sort=sort,
            )
            asset_total = assets["total"]
            for asset in assets["items"]:
                preview_grant = deps.asset_service.create_preview_grant(
                    session=session,
                    source=asset.get("previewSource") or asset.get("thumbnailSource"),
                    mime_type=(asset.get("previewSource") or asset.get("thumbnailSource") or {}).get(
                        "mimeType"
                    ),
                    filename=asset.get("filename"),
                )
                resources.append(_build_image_response(asset, preview_grant))
            asset_offset = _advance_asset_offset(asset_offset, assets, asset_total)
        elif includes_images:
            preview_assets = deps.resourcespace_service.list_assets(
                session,
                query=query,
                container_id=container_id,
                offset=0,
                limit=1,
                sort=sort,
            )
            asset_total = preview_assets["total"]

        new_container_offset = next_container_offset + len(sliced_containers)
        has_more_containers = new_container_offset < len(containers)
        has_more_assets = asset_offset < asset_total
        next_continuation: str | None = None
        if has_more_containers or has_more_assets:
            next_continuation = encode_continuation(
                {
                    "scopeKey": current_scope,
                    "containerOffset": new_container_offset,
                    "assetOffset": asset_offset,
                }
            )

        response_body: dict[str, Any] = {"type": "SUCCESS", "resources": resources}
        if next_continuation:
            response_body["continuation"] = next_continuation
        return JSONResponse(status_code=200, content=response_body, headers=cors_headers(config))
    except Exception as exc:  # noqa: BLE001 — map upstream errors into template errors
        mapped = deps.resourcespace_service.map_error(exc)
        log.warn("content_find_failed", {"code": mapped.code, "message": mapped.message})
        return JSONResponse(
            status_code=200,
            content=_map_find_error(mapped),
            headers=cors_headers(config),
        )


def _map_upload_error(error: ResourceSpaceError) -> tuple[int, dict[str, str]]:
    code = error.code
    if code == "UPSTREAM_SESSION_EXPIRED":
        return 401, {"type": "ERROR", "errorCode": "CONFIGURATION_REQUIRED"}
    if code in ("FORBIDDEN", "UNKNOWN_TENANT"):
        return 403, {"type": "ERROR", "errorCode": "FORBIDDEN"}
    if code == "NOT_FOUND":
        return 404, {"type": "ERROR", "errorCode": "NOT_FOUND"}
    if code in ("INVALID_TENANT_URL", "INVALID_REQUEST"):
        return 400, {"type": "ERROR", "errorCode": "INVALID_REQUEST"}
    if code == "UPSTREAM_UNAVAILABLE":
        return 502, {"type": "ERROR", "errorCode": "TIMEOUT"}
    return 502, {"type": "ERROR", "errorCode": "INTERNAL_ERROR"}


@router.post("/content/resources/upload")
async def content_resources_upload(request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    rate = deps.rate_limiter.consume(
        f"content_upload:{request.client.host if request.client else 'unknown'}"
    )
    if not rate.allowed:
        return json_error(
            config,
            429,
            "RATE_LIMITED",
            "Too many requests.",
            headers={"Retry-After": str(max(1, rate.retry_after_ms // 1000))},
        )

    raw_body = await _raw_body(request)
    # Note: /content/* endpoints are called as browser-direct fetches from
    # the Canva app origin (CORS preflight visible in access logs). The
    # browser can't add the `x-canva-signatures` header — only Canva's
    # server can, and only for server-to-server traffic like webhooks.
    # Bearer-token auth + scope enforcement + the CORS origin lock are the
    # actual security controls here. Signature verification is preserved
    # for genuinely server-to-server endpoints (see routes/webhooks.py).

    token = read_bearer_token(request)
    if not token:
        log.warn("auth_rejected", {"path": request.url.path, "reason": "missing_bearer_token"})
        return json_error(config, 401, "MISSING_BEARER_TOKEN", "Missing bearer token.")
    record = deps.auth_service.read_access_token(token)
    if not record:
        log.warn("auth_rejected", {"path": request.url.path, "reason": "session_expired"})
        return json_error(config, 401, "SESSION_EXPIRED", "Access token is invalid or expired.")
    if not token_has_scope(record, "dam:write"):
        log.warn("auth_rejected", {"path": request.url.path, "reason": "insufficient_scope", "required": "dam:write"})
        return json_error(config, 403, "INSUFFICIENT_SCOPE", "Token is missing the dam:write scope.")

    session = record["session"]
    try:
        body: dict[str, Any] = json.loads(raw_body) if raw_body else {}
    except ValueError:
        return JSONResponse(
            status_code=400,
            content=error_envelope("INVALID_REQUEST", "Request body was not valid JSON."),
            headers=cors_headers(config),
        )

    source_url = body.get("url")
    container_id = body.get("containerId")
    title = body.get("title") or body.get("designTitle")

    if not isinstance(source_url, str) or not source_url.startswith(("http://", "https://")):
        return JSONResponse(
            status_code=400,
            content=error_envelope("INVALID_REQUEST", "A valid `url` is required."),
            headers=cors_headers(config),
        )
    if not isinstance(container_id, str) or not container_id:
        return JSONResponse(
            status_code=400,
            content=error_envelope("INVALID_REQUEST", "A valid `containerId` is required."),
            headers=cors_headers(config),
        )

    try:
        result = deps.resourcespace_service.upload_resource(
            session=session,
            container_id=container_id,
            source_url=source_url,
            title=title if isinstance(title, str) else None,
        )
    except Exception as exc:  # noqa: BLE001
        mapped = deps.resourcespace_service.map_error(exc)
        log.warn("content_upload_failed", {"code": mapped.code, "message": mapped.message})
        status, envelope = _map_upload_error(mapped)
        return JSONResponse(status_code=status, content=envelope, headers=cors_headers(config))

    return JSONResponse(
        status_code=200,
        content={"type": "SUCCESS", "id": result["id"]},
        headers=cors_headers(config),
    )


@router.post("/content/resources/{asset_id}/download-url")
async def content_resources_download_url(asset_id: str, request: Request) -> Response:
    deps = request.app.state.deps
    config = deps.config

    rate = deps.rate_limiter.consume(
        f"content_download:{request.client.host if request.client else 'unknown'}"
    )
    if not rate.allowed:
        return json_error(
            config,
            429,
            "RATE_LIMITED",
            "Too many requests.",
            headers={"Retry-After": str(max(1, rate.retry_after_ms // 1000))},
        )

    token = read_bearer_token(request)
    if not token:
        log.warn("auth_rejected", {"path": request.url.path, "reason": "missing_bearer_token"})
        return json_error(config, 401, "MISSING_BEARER_TOKEN", "Missing bearer token.")
    record = deps.auth_service.read_access_token(token)
    if not record:
        log.warn("auth_rejected", {"path": request.url.path, "reason": "session_expired"})
        return json_error(config, 401, "SESSION_EXPIRED", "Access token is invalid or expired.")
    if not token_has_scope(record, "dam:read"):
        return json_error(config, 403, "INSUFFICIENT_SCOPE", "Token is missing the dam:read scope.")

    session = record["session"]
    try:
        download = deps.resourcespace_service.get_download_source(session, asset_id)
    except Exception as exc:  # noqa: BLE001
        mapped = deps.resourcespace_service.map_error(exc)
        return JSONResponse(
            status_code=mapped.status_code or 500,
            content=error_envelope(mapped.code, mapped.message),
            headers=cors_headers(config),
        )

    grant = deps.asset_service.create_download_grant(
        session=session,
        source=download["source"],
        mime_type=download["mimeType"],
        filename=download["filename"],
    )
    return JSONResponse(
        status_code=200,
        content={
            "type": "SUCCESS",
            "url": grant["url"],
            "expiresAt": grant["expiresAt"],
            "mimeType": download["mimeType"],
        },
        headers=cors_headers(config),
    )
