"""Live-mode ResourceSpace backend (signed-sessionkey HTTP calls)."""
from __future__ import annotations

from datetime import datetime, timezone
from time import monotonic
from typing import Any
from urllib.parse import urlencode

import httpx

from ...config import AppConfig
from ._helpers import (
    SUPPORTED_IMAGE_MIME_TYPES,
    ResourceSpaceError,
    _broker_integration_from_session,
    _build_signed_api_url,
    _decode_collection_container_id,
    _encode_collection_container_id,
    _mime_type_from_extension,
    _pick_asset_description,
    _pick_asset_name,
    _resourcespace_request_headers,
    _sort_collections,
    _to_iso_date,
    pin_request,
)

_LIVE_API_READ_TIMEOUT_SECONDS = 30.0
_LIVE_API_CONNECT_TIMEOUT_SECONDS = 5.0
# Canva's content finder gives up around 20s. Two-phase listing must share one
# budget instead of stacking two full 30s client timeouts.
_LIVE_FIND_BUDGET_SECONDS = 18.0
_LIVE_FIND_MIN_CALL_SECONDS = 0.1
_LIVE_FIND_MAX_LIMIT = 100


def _httpx_timeout(read_seconds: float) -> httpx.Timeout:
    connect = min(_LIVE_API_CONNECT_TIMEOUT_SECONDS, max(read_seconds, 0.001))
    return httpx.Timeout(read_seconds, connect=connect)


def _remaining_find_budget(deadline: float) -> float:
    remaining = deadline - monotonic()
    if remaining < _LIVE_FIND_MIN_CALL_SECONDS:
        raise ResourceSpaceError(
            "UPSTREAM_UNAVAILABLE",
            "ResourceSpace could not be reached.",
            502,
        )
    return remaining


def _first_reachable(pinned_urls: list[str], attempt: Any) -> Any:
    """Call ``attempt(url)`` for each pinned URL in turn, moving to the next on a
    connection error, and return the first response. Provides connection-level
    fallback across a host's validated addresses (e.g. IPv6 then IPv4 where
    outbound IPv6 is disabled). Raises the last connection error if none work."""
    last_exc: httpx.HTTPError | None = None
    for pinned_url in pinned_urls:
        try:
            return attempt(pinned_url)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_exc = exc
    raise last_exc if last_exc is not None else httpx.ConnectError("no validated addresses")


def _parse_jsonish_response(response: httpx.Response) -> Any:
    if response.status_code == 401 or response.status_code == 403:
        raise ResourceSpaceError(
            "UPSTREAM_SESSION_EXPIRED",
            "ResourceSpace session is no longer valid; re-authentication required.",
            401,
        )
    if response.status_code >= 400:
        raise ResourceSpaceError(
            "UPSTREAM_REQUEST_FAILED",
            f"ResourceSpace API request failed with status {response.status_code}.",
            502,
        )
    text = response.text
    try:
        return response.json()
    except ValueError:
        return text


def _fetch_jsonish_sync(
    url: str, *, integration: str | None = None, timeout: float | None = None
) -> Any:
    # Pin the connection to a validated public IP (closes the DNS-rebinding
    # TOCTOU) while preserving the host for TLS SNI/cert and the Host header.
    # trust_env=False: an env HTTPS_PROXY would tunnel via CONNECT and verify TLS
    # against the pinned IP rather than the sni_hostname, breaking the pin.
    pinned_urls, host_headers, extensions = pin_request(url)
    read_timeout = _LIVE_API_READ_TIMEOUT_SECONDS if timeout is None else timeout
    try:
        with httpx.Client(
            timeout=_httpx_timeout(read_timeout),
            trust_env=False,
            headers=_resourcespace_request_headers(integration),
        ) as client:
            response = _first_reachable(
                pinned_urls,
                lambda u: client.get(u, headers=host_headers, extensions=extensions),
            )
    except httpx.HTTPError as exc:
        raise ResourceSpaceError(
            "UPSTREAM_UNAVAILABLE",
            "ResourceSpace could not be reached.",
            502,
        ) from exc
    return _parse_jsonish_response(response)


def _post_jsonish_sync(
    url: str, data: dict[str, str], *, integration: str | None = None
) -> Any:
    pinned_urls, host_headers, extensions = pin_request(url)
    try:
        with httpx.Client(
            timeout=_httpx_timeout(_LIVE_API_READ_TIMEOUT_SECONDS),
            trust_env=False,
            headers=_resourcespace_request_headers(integration),
        ) as client:
            response = _first_reachable(
                pinned_urls,
                lambda u: client.post(
                    u, data=data, headers=host_headers, extensions=extensions
                ),
            )
    except httpx.HTTPError as exc:
        raise ResourceSpaceError(
            "UPSTREAM_UNAVAILABLE",
            "ResourceSpace could not be reached.",
            502,
        ) from exc
    return _parse_jsonish_response(response)


def _authenticate_live_tenant(
    config: AppConfig,
    base_url: str | None,
    username: str,
    password: str,
    *,
    integration: str | None = None,
) -> dict[str, Any]:
    # Imported locally to avoid a circular import: service.py imports from
    # this module at load time, and get_configured_tenant lives there as
    # the facade-level tenant lookup.
    from .service import get_configured_tenant

    tenant = get_configured_tenant(config, base_url)
    # ResourceSpace's execute_api_call() only reads QUERY_STRING or a POST
    # field named `query`. Loose form fields are ignored and login returns
    # an empty HTTP 200, which we map to INVALID_CREDENTIALS.
    result = _post_jsonish_sync(
        tenant["apiUrl"],
        {
            "query": urlencode(
                {"function": "login", "username": username, "password": password}
            )
        },
        integration=integration,
    )
    if result in (False, "false", "", None):
        raise ResourceSpaceError("INVALID_CREDENTIALS", "Invalid ResourceSpace credentials.", 401)
    session_key = str(result)
    return {
        "tenant": tenant,
        "user": {
            "id": f"{tenant['id']}:{username.lower()}",
            "username": username,
            "displayName": username,
            "role": "member",
        },
        "upstream": {
            "mode": "live",
            "sessionKey": session_key,
            "authenticatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }


def _validate_live_sessionkey(
    tenant: dict[str, Any],
    session_key: str,
    username: str,
    *,
    integration: str | None = None,
) -> dict[str, Any]:
    """Validate a ResourceSpace session key handed back by the hosted-login
    flow, then build the bridge session.

    The signed ``get_resource_types`` call is the identity cross-check: RS
    resolves the signing key from the ``user`` parameter, so a valid signature
    proves the username and session key are a matching pair. The function takes
    no parameters and returns the resource types available to the authenticated
    user as a JSON array. Validity is defined strictly as "the response decodes
    to a JSON list" (an empty list is still treated as authenticated). ResourceSpace
    signals failure with HTTP 200 + a falsy body (``false`` / ``""`` / ``null``)
    as often as with 401/403, so anything that is not a list is treated as a
    failed validation and must not mint a token.
    """
    result = _call_live_api(
        tenant=tenant,
        username=username,
        session_key=session_key,
        params={"function": "get_resource_types"},
        integration=integration,
    )
    if not isinstance(result, list):
        raise ResourceSpaceError(
            "UPSTREAM_SESSION_EXPIRED",
            "ResourceSpace session key did not validate.",
            401,
        )
    return {
        "tenant": tenant,
        "user": {
            "id": f"{tenant['id']}:{username.lower()}",
            "username": username,
            "displayName": username,
            "role": "member",
        },
        "upstream": {
            "mode": "live",
            "sessionKey": session_key,
            "authenticatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    }


def _build_live_collection_container(
    collection: dict[str, Any], tenant: dict[str, Any], child_count: int = 0
) -> dict[str, Any]:
    return {
        "id": _encode_collection_container_id(collection.get("ref")),
        "type": "CONTAINER",
        "name": collection.get("name") or f"Collection {collection.get('ref')}",
        "containerType": "folder",
        "description": f"Collection {collection.get('ref')}" if tenant.get("rootCollections") else None,
        "numContainers": child_count,
        "access": "read-write",
    }


def _apply_configured_collection_tree(
    tenant: dict[str, Any], collections: list[dict[str, Any]], parent_id: str | None
) -> list[dict[str, Any]]:
    lookup = {str(collection.get("ref")): collection for collection in collections}
    child_map = tenant.get("collectionChildren") or {}
    root_refs = tenant.get("rootCollections") or []

    if root_refs:
        current_ids = (
            [str(ref) for ref in root_refs]
            if parent_id is None
            else [str(ref) for ref in child_map.get(str(parent_id), [])]
        )
        return [
            lookup.get(str(ref), {"ref": ref, "name": f"Collection {ref}"})
            for ref in current_ids
        ]

    if parent_id is not None:
        return []
    return collections


# ResourceSpace !properties is a SQL filter and must be the first token, so it
# cannot be combined with !collection. fext:-tif excludes TIFF originals that
# otherwise force search_get_previews to generate JPEG previews (often >20s).
_LIVE_UNSUPPORTED_EXTENSION_FILTER = "!propertiesfext:-tif;fext:-tiff"


def build_live_search_string(query: str, container_id: str | None) -> str:
    search = (query or "").strip()
    collection_ref = _decode_collection_container_id(container_id) if container_id else None
    if collection_ref and search:
        return f"!collection{collection_ref} {search}"
    if collection_ref:
        return f"!collection{collection_ref}"
    # ResourceSpace exact-ref match only fires when the whole search is the
    # integer or !resourceN. Prefixing !properties would hide that hit.
    if search.isdigit():
        return f"!resource{search}"
    if search:
        return f"{_LIVE_UNSUPPORTED_EXTENSION_FILTER} {search}"
    return _LIVE_UNSUPPORTED_EXTENSION_FILTER


def build_live_preview_list_search(refs: list[str]) -> str:
    return "!list" + ":".join(refs)


def _live_search_records(response: Any) -> tuple[int, list[dict[str, Any]]]:
    if isinstance(response, dict):
        total = int(response.get("total", 0) or 0)
        items = response.get("data") if isinstance(response.get("data"), list) else []
    elif isinstance(response, list):
        items = response
        total = len(items)
    else:
        return 0, []
    return total, [item for item in items if isinstance(item, dict)]


def _supported_live_record(record: dict[str, Any]) -> bool:
    extension = str(record.get("file_extension") or record.get("preview_extension") or "jpg").lower()
    return _mime_type_from_extension(extension) in SUPPORTED_IMAGE_MIME_TYPES


def build_live_asset(record: dict[str, Any]) -> dict[str, Any]:
    extension = str(record.get("file_extension") or record.get("preview_extension") or "jpg").lower()
    mime_type = _mime_type_from_extension(extension)
    thumb_width = int(record.get("thumb_width") or record.get("image_width") or 0) or None
    thumb_height = int(record.get("thumb_height") or record.get("image_height") or 0) or None

    thumb_source: dict[str, Any] | None = None
    if record.get("url_thm"):
        thumb_source = {
            "kind": "proxy",
            "url": record["url_thm"],
            "mimeType": _mime_type_from_extension(record.get("preview_extension") or "jpg"),
            "width": int(record.get("thumb_width") or 0) or None,
            "height": int(record.get("thumb_height") or 0) or None,
        }

    preview_url = record.get("url_pre") or record.get("url_thm")
    preview_source: dict[str, Any] | None = None
    if preview_url:
        preview_source = {
            "kind": "proxy",
            "url": preview_url,
            "mimeType": _mime_type_from_extension(record.get("preview_extension") or "jpg"),
            "width": int(record.get("thumb_width") or 0) or None,
            "height": int(record.get("thumb_height") or 0) or None,
        }

    return {
        "id": str(record.get("ref")),
        "type": "IMAGE",
        "name": _pick_asset_name(record),
        "description": _pick_asset_description(record),
        "mimeType": mime_type,
        "filename": record.get("original_filename") or f"{record.get('ref')}.{extension}",
        "width": thumb_width,
        "height": thumb_height,
        "createdAt": _to_iso_date(record.get("creation_date")),
        "updatedAt": _to_iso_date(record.get("file_modified")),
        "thumbnailSource": thumb_source,
        "previewSource": preview_source,
    }


def normalize_live_asset_page(response: Any) -> dict[str, Any]:
    total, items = _live_search_records(response)
    mapped = [
        asset
        for asset in (build_live_asset(item) for item in items)
        if asset["mimeType"] in SUPPORTED_IMAGE_MIME_TYPES and asset["thumbnailSource"] is not None
    ]
    return {"items": mapped, "total": total}


def _require_live_search_payload(response: Any) -> None:
    if isinstance(response, (dict, list)):
        return
    raise ResourceSpaceError(
        "UPSTREAM_REQUEST_FAILED",
        "ResourceSpace preview listing did not return search results.",
        502,
    )


def _call_live_api(
    *,
    tenant: dict[str, Any],
    username: str,
    session_key: str,
    params: dict[str, Any],
    integration: str | None = None,
    timeout: float | None = None,
) -> Any:
    url = _build_signed_api_url(
        api_url=tenant["apiUrl"],
        username=username,
        session_key=session_key,
        params=params,
    )
    return _fetch_jsonish_sync(url, integration=integration, timeout=timeout)


def _list_live_containers(session: dict[str, Any], parent_id: str | None) -> list[dict[str, Any]]:
    collections = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        params={"function": "get_user_collections"},
        integration=_broker_integration_from_session(session),
    )
    current_parent_ref = _decode_collection_container_id(parent_id) if parent_id else None
    scoped = _apply_configured_collection_tree(
        session["tenant"],
        collections if isinstance(collections, list) else [],
        current_parent_ref,
    )
    return [
        _build_live_collection_container(
            collection,
            session["tenant"],
            len((session["tenant"].get("collectionChildren") or {}).get(str(collection.get("ref")), [])),
        )
        for collection in _sort_collections(scoped)
    ]


def _search_live_containers(
    session: dict[str, Any], parent_id: str | None, query: str
) -> list[dict[str, Any]]:
    containers = _list_live_containers(session, parent_id)
    normalized = query.strip().lower()
    return [container for container in containers if normalized in container["name"].lower()]


def _list_live_assets(
    session: dict[str, Any],
    *,
    query: str,
    container_id: str | None,
    offset: int,
    limit: int,
    sort: str,
) -> dict[str, Any]:
    # List first without preview URLs, then resolve thumbs only for Canva-
    # supported originals. search_get_previews with getsizes can spend tens of
    # seconds generating JPEG previews for TIFFs that the sidebar then drops.
    order_by = "title" if sort == "name_asc" else "date"
    sort_direction = "asc" if sort == "updated_asc" else "desc"
    search = build_live_search_string(query, container_id)
    offset = max(0, int(offset))
    limit = max(1, min(int(limit), _LIVE_FIND_MAX_LIMIT))
    common = {
        "order_by": order_by,
        "sort": sort_direction,
        "archive": 0,
        "previewext": "jpg",
    }
    deadline = monotonic() + _LIVE_FIND_BUDGET_SECONDS
    listing = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        integration=_broker_integration_from_session(session),
        timeout=_remaining_find_budget(deadline),
        params={
            "function": "search_get_previews",
            "search": search,
            "fetchrows": f"{offset},{limit}",
            **common,
        },
    )
    _require_live_search_payload(listing)
    total, records = _live_search_records(listing)
    refs = [
        str(record["ref"])
        for record in records
        if record.get("ref") is not None and _supported_live_record(record)
    ]
    if not refs:
        return {"items": [], "total": total, "scanned": len(records)}

    previews = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        integration=_broker_integration_from_session(session),
        timeout=_remaining_find_budget(deadline),
        params={
            "function": "search_get_previews",
            "search": build_live_preview_list_search(refs),
            "fetchrows": f"0,{len(refs)}",
            "getsizes": "thm,pre",
            **common,
        },
    )
    _require_live_search_payload(previews)
    page = normalize_live_asset_page(previews)
    by_id = {asset["id"]: asset for asset in page["items"]}
    return {
        "items": [by_id[ref] for ref in refs if ref in by_id],
        "total": total,
        "scanned": len(records),
    }


def _get_live_download_source(session: dict[str, Any], asset_id: str) -> dict[str, Any]:
    resource = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        params={"function": "get_resource_data", "resource": asset_id},
        integration=_broker_integration_from_session(session),
    )
    if not resource or resource in (False, "false"):
        raise ResourceSpaceError("NOT_FOUND", "Asset not found.", 404)

    extension = resource.get("file_extension") or resource.get("preview_extension") or "jpg"
    mime_type = _mime_type_from_extension(extension)
    if mime_type not in SUPPORTED_IMAGE_MIME_TYPES:
        raise ResourceSpaceError("UNSUPPORTED_FORMAT", "Unsupported asset format.", 409)

    original_url = _call_live_api(
        tenant=session["tenant"],
        username=session["user"]["username"],
        session_key=session["upstream"]["sessionKey"],
        integration=_broker_integration_from_session(session),
        params={
            "function": "get_resource_path",
            "ref": asset_id,
            "extension": extension,
            "page": 1,
            "watermarked": 0,
        },
    )
    if not original_url or original_url in (False, "false"):
        raise ResourceSpaceError("NOT_FOUND", "Asset download URL was not available.", 404)

    return {
        "source": {"kind": "proxy", "url": str(original_url), "mimeType": mime_type},
        "mimeType": mime_type,
        "filename": resource.get("original_filename") or f"{asset_id}.{extension}",
    }
