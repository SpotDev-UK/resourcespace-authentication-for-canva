"""FastAPI application factory + uvicorn entrypoint."""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from . import logger as log
from .config import AppConfig, create_config, validate_config_for_environment
from .dependencies import Dependencies, build_dependencies
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

    app = FastAPI(
        title="ResourceSpace Canva Platform Broker",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
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
        },
    )
    uvicorn.run(
        "resourcespace_platform.main:create_app",
        host="0.0.0.0",
        port=config.port,
        factory=True,
        log_level="info",
    )


if __name__ == "__main__":
    run()
