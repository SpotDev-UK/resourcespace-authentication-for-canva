"""FastAPI application factory + uvicorn entrypoint."""
from __future__ import annotations

import asyncio
import contextlib
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from . import logger as log
from .config import AppConfig, create_config, validate_config_for_environment
from .dependencies import Dependencies, build_dependencies
from .services.json_store import JsonStoreLoadError
from .http_utils import cors_headers, error_envelope
from .routes import assets as assets_routes
from .routes import content as content_routes
from .routes import health as health_routes
from .routes import oauth as oauth_routes
from .routes import session as session_routes
from .routes import webhooks as webhooks_routes


def create_app(config: AppConfig | None = None) -> FastAPI:
    resolved_config = config or create_config()
    # Refuse to start in non-development environments if security-critical
    # config is missing. Raises ConfigValidationError with a precise list of
    # what to set.
    validate_config_for_environment(resolved_config)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        deps: Dependencies = app.state.deps
        prune_task: asyncio.Task[None] | None = None
        interval = deps.config.store_prune_interval_seconds
        if interval > 0:

            async def _prune_loop() -> None:
                while True:
                    await asyncio.sleep(interval)
                    try:
                        await asyncio.to_thread(deps.auth_service.prune)
                    except (JsonStoreLoadError, Exception) as exc:
                        log.warn("store_prune_failed", {"error": str(exc)})

            prune_task = asyncio.create_task(_prune_loop())
        yield
        if prune_task is not None:
            prune_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await prune_task

    app = FastAPI(
        title="ResourceSpace Canva Platform Broker",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.deps = build_dependencies(resolved_config)

    cors_origins = [
        origin.strip()
        for origin in resolved_config.cors_origin.split(",")
        if origin.strip()
    ] or ["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=[
            "authorization",
            "content-type",
            "x-canva-signatures",
            "x-canva-timestamp",
        ],
    )

    app.include_router(health_routes.router)
    app.include_router(oauth_routes.router)
    app.include_router(session_routes.router)
    app.include_router(content_routes.router)
    app.include_router(assets_routes.router)
    app.include_router(webhooks_routes.router)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> Response:
        log.error(
            "request_failed",
            {"path": str(request.url.path), "error": str(exc)},
        )
        return JSONResponse(
            status_code=500,
            content=error_envelope("INTERNAL_ERROR", "Unexpected server error."),
            headers=cors_headers(resolved_config),
        )

    return app


def run() -> None:
    import uvicorn

    config = create_config()
    log.info(
        "platform_server_starting",
        {
            "port": config.port,
            "baseUrl": config.base_url,
            "environment": config.environment,
            "resourceSpaceMode": config.resource_space.mode,
            "clientIpHeader": config.client_ip_header or None,
            "trustedProxyHosts": config.trusted_proxy_hosts,
            "uvicornProxyHeaders": False,
        },
    )
    # Client IP resolution is handled in application code (resolve_client_host)
    # using TRUSTED_PROXY_HOSTS + CLIENT_IP_HEADER. Uvicorn's ProxyHeadersMiddleware
    # rewrites request.client from X-Forwarded-For before the app runs, which
    # hides the transport peer and can override the configured x-real-ip path.
    uvicorn.run(
        "resourcespace_platform.main:create_app",
        host="0.0.0.0",
        port=config.port,
        factory=True,
        log_level="info",
        proxy_headers=False,
    )


if __name__ == "__main__":
    run()
