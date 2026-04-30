"""ResourceSpace integration package (facade over fixture + live backends)."""
from __future__ import annotations

from ._helpers import ResourceSpaceError
from ._live_backend import (
    build_live_asset,
    build_live_search_string,
    normalize_live_asset_page,
)
from .service import (
    ResourceSpaceService,
    create_resourcespace_service,
    get_configured_tenant,
)

__all__ = [
    "ResourceSpaceError",
    "ResourceSpaceService",
    "build_live_asset",
    "build_live_search_string",
    "create_resourcespace_service",
    "get_configured_tenant",
    "normalize_live_asset_page",
]
