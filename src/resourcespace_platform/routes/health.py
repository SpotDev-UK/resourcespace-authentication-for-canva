"""Health, readiness, and metrics endpoints.

Public health/readiness checks return only the minimum needed to confirm the
broker is running. They do not expose deployment posture (environment,
verification mode, ResourceSpace mode), since that data tells an attacker
which security controls are in play.

`/metrics` returns aggregate counts only by default. When ``METRICS_TOKEN``
is configured, the endpoint also accepts a bearer token and returns the
extended posture/admin payload to authorised callers.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..http_utils import cors_headers, json_error, read_bearer_token


router = APIRouter()


@router.get("/")
def root(request: Request) -> JSONResponse:
    deps = request.app.state.deps
    return JSONResponse(
        status_code=200,
        content={
            "service": "ResourceSpace Canva Platform Broker",
            "ok": True,
            "endpoints": {
                "healthz": "/healthz",
                "readyz": "/readyz",
                "metrics": "/metrics",
                "authorise": "/oauth/authorise",
            },
        },
        headers=cors_headers(deps.config),
    )


@router.get("/healthz")
def healthz(request: Request) -> JSONResponse:
    deps = request.app.state.deps
    return JSONResponse(
        status_code=200,
        content={"ok": True},
        headers=cors_headers(deps.config),
    )


@router.get("/readyz")
def readyz(request: Request) -> JSONResponse:
    deps = request.app.state.deps
    return JSONResponse(
        status_code=200,
        content={"ok": True},
        headers=cors_headers(deps.config),
    )


@router.get("/metrics")
def metrics(request: Request) -> JSONResponse:
    deps = request.app.state.deps
    config = deps.config
    base_payload = {"auth": deps.auth_service.get_stats()}

    expected_token = config.metrics.bearer_token
    if not expected_token:
        return JSONResponse(status_code=200, content=base_payload, headers=cors_headers(config))

    presented = read_bearer_token(request)
    if not presented or not secrets.compare_digest(presented, expected_token):
        return json_error(config, 401, "UNAUTHORIZED", "Unauthorized.")

    extended = {
        **base_payload,
        "environment": config.environment,
        "resourceSpaceMode": config.resource_space.mode,
        "requestVerificationMode": config.signing.request_verification_mode,
    }
    return JSONResponse(status_code=200, content=extended, headers=cors_headers(config))
