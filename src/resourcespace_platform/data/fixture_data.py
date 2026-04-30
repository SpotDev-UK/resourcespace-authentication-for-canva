"""Development fixture data — tenants, users, containers, assets.

Mirrors the Node fixture so local dev and automated tests behave identically.
Fixture mode is NOT the release path; `RESOURCE_SPACE_MODE=live` is.
"""
from __future__ import annotations

from typing import Any


TENANTS: list[dict[str, Any]] = [
    {
        "id": "tenant_acme",
        "slug": "acme",
        "name": "Acme Brands UAT",
        "baseUrl": "https://acme.demo.resourcespace.local",
    },
    {
        "id": "tenant_globex",
        "slug": "globex",
        "name": "Globex Media UAT",
        "baseUrl": "https://globex.demo.resourcespace.local",
    },
]


USERS: list[dict[str, Any]] = [
    {
        "id": "user_alice",
        "username": "alice",
        "password": "alice-password",
        "displayName": "Alice Admin",
        "tenantId": "tenant_acme",
        "role": "admin",
    },
    {
        "id": "user_bob",
        "username": "bob",
        "password": "bob-password",
        "displayName": "Bob Brand Manager",
        "tenantId": "tenant_acme",
        "role": "editor",
    },
    {
        "id": "user_clara",
        "username": "clara",
        "password": "clara-password",
        "displayName": "Clara Curator",
        "tenantId": "tenant_globex",
        "role": "admin",
    },
]


CONTAINERS: list[dict[str, Any]] = [
    {"id": "container_acme_root", "tenantId": "tenant_acme", "parentId": None, "name": "Brand Library"},
    {"id": "container_acme_campaigns", "tenantId": "tenant_acme", "parentId": "container_acme_root", "name": "Campaigns"},
    {"id": "container_acme_social", "tenantId": "tenant_acme", "parentId": "container_acme_root", "name": "Social"},
    {"id": "container_globex_root", "tenantId": "tenant_globex", "parentId": None, "name": "Launch Assets"},
    {"id": "container_globex_evergreen", "tenantId": "tenant_globex", "parentId": "container_globex_root", "name": "Evergreen"},
]


ASSETS: list[dict[str, Any]] = [
    {
        "id": "asset_summer_hero",
        "tenantId": "tenant_acme",
        "containerId": "container_acme_campaigns",
        "title": "Summer Hero Banner",
        "summary": "Primary hero image for seasonal campaign work.",
        "mimeType": "image/svg+xml",
        "filename": "summer-hero.svg",
        "width": 1600,
        "height": 900,
        "accent": "#ffb703",
        "createdAt": "2026-03-02T09:15:00.000Z",
        "updatedAt": "2026-04-01T08:45:00.000Z",
    },
    {
        "id": "asset_social_tiles",
        "tenantId": "tenant_acme",
        "containerId": "container_acme_social",
        "title": "Social Tiles Pack",
        "summary": "Square social pack for paid and organic posts.",
        "mimeType": "image/svg+xml",
        "filename": "social-tiles.svg",
        "width": 1080,
        "height": 1080,
        "accent": "#219ebc",
        "createdAt": "2026-03-10T12:00:00.000Z",
        "updatedAt": "2026-04-08T16:00:00.000Z",
    },
    {
        "id": "asset_board_minutes",
        "tenantId": "tenant_acme",
        "containerId": "container_acme_root",
        "title": "Board Minutes Scan",
        "summary": "Visible but not importable because TIFF is out of scope for Phase 1.",
        "mimeType": "image/tiff",
        "filename": "board-minutes.tiff",
        "width": 1400,
        "height": 1400,
        "accent": "#8d99ae",
        "createdAt": "2026-02-01T10:00:00.000Z",
        "updatedAt": "2026-02-01T10:00:00.000Z",
    },
    {
        "id": "asset_confidential_strategy",
        "tenantId": "tenant_acme",
        "containerId": "container_acme_campaigns",
        "title": "Confidential Strategy Sheet",
        "summary": "Visible only to Alice inside the tenant.",
        "mimeType": "image/svg+xml",
        "filename": "confidential-strategy.svg",
        "width": 1400,
        "height": 900,
        "accent": "#ef476f",
        "restrictedTo": ["user_alice"],
        "createdAt": "2026-03-18T10:00:00.000Z",
        "updatedAt": "2026-03-18T10:00:00.000Z",
    },
    {
        "id": "asset_globex_product",
        "tenantId": "tenant_globex",
        "containerId": "container_globex_root",
        "title": "Globex Product Showcase",
        "summary": "Launch imagery for product showcase collateral.",
        "mimeType": "image/svg+xml",
        "filename": "globex-product-showcase.svg",
        "width": 1400,
        "height": 900,
        "accent": "#8338ec",
        "createdAt": "2026-03-28T10:00:00.000Z",
        "updatedAt": "2026-04-04T10:00:00.000Z",
    },
    {
        "id": "asset_globex_logo",
        "tenantId": "tenant_globex",
        "containerId": "container_globex_evergreen",
        "title": "Globex Logo Lockup",
        "summary": "Evergreen logo treatment for general brand use.",
        "mimeType": "image/svg+xml",
        "filename": "globex-logo-lockup.svg",
        "width": 1200,
        "height": 700,
        "accent": "#06d6a0",
        "createdAt": "2026-01-11T10:00:00.000Z",
        "updatedAt": "2026-03-11T10:00:00.000Z",
    },
]


SUPPORTED_IMPORT_MIME_TYPES: frozenset[str] = frozenset(
    {"image/jpeg", "image/png", "image/svg+xml", "image/webp"}
)


def get_tenant_by_base_url(base_url: str) -> dict[str, Any] | None:
    for tenant in TENANTS:
        if tenant["baseUrl"] == base_url:
            return tenant
    return None


def get_tenant_by_id(tenant_id: str) -> dict[str, Any] | None:
    for tenant in TENANTS:
        if tenant["id"] == tenant_id:
            return tenant
    return None


def get_user_by_tenant_and_username(tenant_id: str, username: str) -> dict[str, Any] | None:
    normalized = username.lower()
    for user in USERS:
        if user["tenantId"] == tenant_id and user["username"].lower() == normalized:
            return user
    return None


def get_user_by_id(user_id: str) -> dict[str, Any] | None:
    for user in USERS:
        if user["id"] == user_id:
            return user
    return None


def can_user_see_asset(user: dict[str, Any] | None, asset: dict[str, Any]) -> bool:
    if not user or user["tenantId"] != asset["tenantId"]:
        return False
    restricted = asset.get("restrictedTo")
    if not restricted:
        return True
    return user["id"] in restricted


def get_container_by_id(container_id: str | None) -> dict[str, Any] | None:
    if container_id is None:
        return None
    for container in CONTAINERS:
        if container["id"] == container_id:
            return container
    return None


def get_container_path(container_id: str | None) -> str:
    parts: list[str] = []
    current = container_id
    while current:
        container = get_container_by_id(current)
        if not container:
            break
        parts.insert(0, container["name"])
        current = container["parentId"]
    return " / ".join(parts)


def list_child_containers(tenant_id: str, parent_id: str | None = None) -> list[dict[str, Any]]:
    return [
        container
        for container in CONTAINERS
        if container["tenantId"] == tenant_id and container["parentId"] == parent_id
    ]


def _is_asset_in_container_subtree(asset: dict[str, Any], container_id: str | None) -> bool:
    if not container_id:
        return True
    current = asset["containerId"]
    while current:
        if current == container_id:
            return True
        parent = get_container_by_id(current)
        current = parent["parentId"] if parent else None
    return False


def search_visible_assets(
    user: dict[str, Any] | None,
    *,
    query: str = "",
    container_id: str | None = None,
) -> list[dict[str, Any]]:
    normalized = query.strip().lower()
    results: list[dict[str, Any]] = []
    for asset in ASSETS:
        if not can_user_see_asset(user, asset):
            continue
        if not _is_asset_in_container_subtree(asset, container_id):
            continue
        if normalized:
            haystack = " ".join(
                filter(
                    None,
                    [asset["title"], asset["summary"], get_container_path(asset["containerId"])],
                )
            ).lower()
            if normalized not in haystack:
                continue
        results.append(asset)
    return results


def sort_assets(entries: list[dict[str, Any]], sort: str = "updated_desc") -> list[dict[str, Any]]:
    items = list(entries)
    if sort == "name_asc":
        items.sort(key=lambda asset: asset["title"])
    elif sort == "updated_asc":
        items.sort(key=lambda asset: asset["updatedAt"])
    else:
        items.sort(key=lambda asset: asset["updatedAt"], reverse=True)
    return items


def get_asset_by_id(asset_id: str) -> dict[str, Any] | None:
    for asset in ASSETS:
        if asset["id"] == asset_id:
            return asset
    return None


def is_asset_importable(asset: dict[str, Any]) -> bool:
    return asset["mimeType"] in SUPPORTED_IMPORT_MIME_TYPES


def _escape_xml(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def render_fixture_svg(asset: dict[str, Any], variant: str = "preview") -> str:
    width = 480 if variant == "thumbnail" else asset["width"]
    height = 320 if variant == "thumbnail" else asset["height"]
    title_size = 28 if variant == "thumbnail" else 46
    subtitle_size = 14 if variant == "thumbnail" else 24
    container_path = get_container_path(asset["containerId"])
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">\n'
        "  <defs>\n"
        '    <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">\n'
        f'      <stop offset="0%" stop-color="{asset["accent"]}"/>\n'
        '      <stop offset="100%" stop-color="#0b1020"/>\n'
        "    </linearGradient>\n"
        "  </defs>\n"
        f'  <rect width="{width}" height="{height}" rx="24" fill="url(#bg)"/>\n'
        f'  <circle cx="{round(width * 0.82)}" cy="{round(height * 0.18)}" '
        f'r="{round(width * 0.12)}" fill="rgba(255,255,255,0.12)"/>\n'
        f'  <text x="48" y="{round(height * 0.42)}" fill="#ffffff" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="{title_size}" font-weight="700">\n'
        f'    {_escape_xml(asset["title"])}\n'
        "  </text>\n"
        f'  <text x="48" y="{round(height * 0.54)}" fill="#edf2f4" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="{subtitle_size}">\n'
        f'    {_escape_xml(asset["summary"])}\n'
        "  </text>\n"
        f'  <text x="48" y="{height - 32}" fill="#edf2f4" '
        f'font-family="Helvetica, Arial, sans-serif" font-size="{subtitle_size}">\n'
        f"    {_escape_xml(container_path)}\n"
        "  </text>\n"
        "</svg>"
    )
