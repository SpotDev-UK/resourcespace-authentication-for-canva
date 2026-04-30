"""ResourceSpace service helper tests.

Mirrors the Node `resourcespace-service.test.js` suite.
"""
from __future__ import annotations

import json

import pytest

from resourcespace_platform.config import create_config
from resourcespace_platform.services.resourcespace import (
    ResourceSpaceError,
    build_live_asset,
    build_live_search_string,
    get_configured_tenant,
    normalize_live_asset_page,
)


def test_get_configured_tenant_resolves_explicit_tenants_and_allowlisted_hosts() -> None:
    config = create_config(
        {
            "RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com",
            "RESOURCE_SPACE_TENANTS_JSON": json.dumps(
                [
                    {
                        "id": "tenant_curated",
                        "slug": "curated",
                        "name": "Curated UAT",
                        "baseUrl": "https://curated.resourcespace.example.com",
                        "apiUrl": "https://api.curated.resourcespace.example.com/",
                    }
                ]
            ),
        }
    )

    configured = get_configured_tenant(
        config, "https://curated.resourcespace.example.com/"
    )
    assert configured["id"] == "tenant_curated"
    assert configured["apiUrl"] == "https://api.curated.resourcespace.example.com/"

    allowlisted = get_configured_tenant(
        config, "https://brand.resourcespace.example.com/path/to/app"
    )
    assert allowlisted["id"] == "tenant_brand-resourcespace-example-com"
    assert allowlisted["baseUrl"] == "https://brand.resourcespace.example.com"
    assert allowlisted["apiUrl"] == "https://brand.resourcespace.example.com/api/"


def test_get_configured_tenant_strips_query_and_fragment_from_tenant_url() -> None:
    config = create_config({"RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com"})

    configured = get_configured_tenant(
        config, "https://brand.resourcespace.example.com/pages/view?page=42#section"
    )

    assert configured["baseUrl"] == "https://brand.resourcespace.example.com"
    assert configured["apiUrl"] == "https://brand.resourcespace.example.com/api/"


def test_get_configured_tenant_rejects_non_allowlisted_hosts() -> None:
    config = create_config({"RESOURCE_SPACE_ALLOWED_HOSTS": ".resourcespace.example.com"})
    with pytest.raises(ResourceSpaceError) as excinfo:
        get_configured_tenant(config, "https://example.org")
    assert excinfo.value.code == "UNKNOWN_TENANT"


def test_build_live_search_string_scopes_search_to_collections() -> None:
    assert build_live_search_string("", None) == ""
    assert build_live_search_string("hero", None) == "hero"
    assert build_live_search_string("", "collection:42") == "!collection42"
    assert build_live_search_string("hero banner", "collection:42") == "!collection42 hero banner"


def test_build_live_asset_maps_previews_and_metadata() -> None:
    asset = build_live_asset(
        {
            "ref": 101,
            "title": "Homepage Hero",
            "original_filename": "homepage-hero.png",
            "file_extension": "png",
            "preview_extension": "jpg",
            "thumb_width": 640,
            "thumb_height": 360,
            "image_width": 2400,
            "image_height": 1350,
            "creation_date": "2026-04-10T10:00:00Z",
            "file_modified": "2026-04-11T12:30:00Z",
            "url_thm": "https://assets.example.com/hero-thm.jpg",
            "url_pre": "https://assets.example.com/hero-pre.jpg",
        }
    )

    assert asset["id"] == "101"
    assert asset["mimeType"] == "image/png"
    assert asset["thumbnailSource"]["url"] == "https://assets.example.com/hero-thm.jpg"
    assert asset["previewSource"]["url"] == "https://assets.example.com/hero-pre.jpg"
    assert asset["width"] == 640
    assert asset["height"] == 360


def test_normalize_live_asset_page_keeps_supported_and_drops_unsupported() -> None:
    page = normalize_live_asset_page(
        {
            "total": 3,
            "data": [
                {
                    "ref": 101,
                    "title": "Keep Me",
                    "original_filename": "keep-me.png",
                    "file_extension": "png",
                    "preview_extension": "jpg",
                    "thumb_width": 640,
                    "thumb_height": 360,
                    "url_thm": "https://assets.example.com/keep-me-thm.jpg",
                },
                {
                    "ref": 102,
                    "title": "Unsupported TIFF",
                    "original_filename": "unsupported.tiff",
                    "file_extension": "tiff",
                    "preview_extension": "jpg",
                    "thumb_width": 640,
                    "thumb_height": 360,
                    "url_thm": "https://assets.example.com/unsupported-thm.jpg",
                },
                {
                    "ref": 103,
                    "title": "Missing Thumbnail",
                    "original_filename": "missing-thumb.jpg",
                    "file_extension": "jpg",
                },
            ],
        }
    )

    assert page["total"] == 3
    assert len(page["items"]) == 1
    assert page["items"][0]["id"] == "101"
