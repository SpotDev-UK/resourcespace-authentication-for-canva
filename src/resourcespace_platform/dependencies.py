"""Application-scoped service container.

Built once at startup, shared across requests. Exposed to routes via
`Request.app.state.deps`.
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import AppConfig
from .services.asset_service import AssetService, create_asset_service
from .services.auth_service import AuthService, create_auth_service
from .services.json_store import JsonStore, create_json_store
from .services.rate_limiter import RateLimiter, create_rate_limiter
from .services.resourcespace import ResourceSpaceService, create_resourcespace_service


@dataclass
class Dependencies:
    config: AppConfig
    store: JsonStore
    resourcespace_service: ResourceSpaceService
    auth_service: AuthService
    asset_service: AssetService
    rate_limiter: RateLimiter


def build_dependencies(config: AppConfig) -> Dependencies:
    store = create_json_store(config.storage_path)
    resourcespace_service = create_resourcespace_service(config)
    auth_service = create_auth_service(
        config=config,
        store=store,
        resourcespace_service=resourcespace_service,
    )
    asset_service = create_asset_service(config=config, store=store)
    rate_limiter = create_rate_limiter(
        max_requests=config.rate_limit.max_requests,
        window_ms=config.rate_limit.window_ms,
    )
    return Dependencies(
        config=config,
        store=store,
        resourcespace_service=resourcespace_service,
        auth_service=auth_service,
        asset_service=asset_service,
        rate_limiter=rate_limiter,
    )
