"""Upload / preview-generation helpers for live ResourceSpace tenants."""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

import httpx

from ...config import AppConfig
from ._helpers import (
    ResourceSpaceError,
    _broker_integration_from_session,
    _build_signed_api_url,
    _canonical_pattern,
    _is_private_ip,
    _resourcespace_request_headers,
    canonical_ascii_host,
    pin_request,
)
from ._live_backend import _call_live_api, _first_reachable


# Reasonable absolute ceiling for Pillow's anti-decompression-bomb guard.
# Overridden per-request from `AppConfig.upload.max_image_pixels` when the
# upload helper is called, so deployers can tighten further.
_DEFAULT_MAX_IMAGE_PIXELS = 50_000_000


class _PreviewGenerationError(Exception):
    """Raised when a preview JPEG cannot be produced from source bytes."""


def _build_jpeg_preview(source_bytes: bytes, *, max_image_pixels: int) -> bytes:
    try:
        from io import BytesIO

        from PIL import Image  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover — Pillow is a runtime dep
        raise _PreviewGenerationError("Pillow is not installed") from exc

    # Cap Pillow's allocation guard so a deliberately oversized header
    # cannot trigger an unbounded allocation.
    Image.MAX_IMAGE_PIXELS = max_image_pixels

    try:
        with Image.open(BytesIO(source_bytes)) as image:
            rgb = image.convert("RGB")
            rgb.thumbnail((1000, 1000))
            buf = BytesIO()
            rgb.save(buf, format="JPEG", quality=85, optimize=True)
            return buf.getvalue()
    except Exception as exc:  # noqa: BLE001 — Pillow raises many subclasses
        raise _PreviewGenerationError(str(exc)) from exc


def _validate_export_url(url: str, config: AppConfig) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ResourceSpaceError(
            "INVALID_REQUEST",
            "Export URLs must use https.",
            400,
        )
    # Canonicalise (UTS46) the host and the configured patterns together, so a
    # Unicode host and a Unicode allowlist pattern match consistently and match
    # the host that is actually resolved/connected to.
    host = canonical_ascii_host(parsed.hostname or "")
    if not host:
        raise ResourceSpaceError(
            "INVALID_REQUEST",
            "Export URL is missing a hostname.",
            400,
        )

    allowed_hosts = [_canonical_pattern(h) for h in config.upload.allowed_hosts]
    if allowed_hosts:
        if host not in allowed_hosts and not any(
            host.endswith("." + h.lstrip(".")) for h in allowed_hosts if h.startswith(".")
        ):
            raise ResourceSpaceError(
                "FORBIDDEN",
                "Export URL host is not in CANVA_UPLOAD_ALLOWED_HOSTS.",
                403,
            )

    if _is_private_ip(host):
        raise ResourceSpaceError(
            "FORBIDDEN",
            "Export URL resolves to a private network address.",
            403,
        )


def _post_multipart_live_api(
    *,
    tenant: dict[str, Any],
    username: str,
    session_key: str,
    params: dict[str, Any],
    file_bytes: bytes,
    filename: str,
    content_type: str,
    integration: str | None = None,
) -> Any:
    """POST a multipart upload. On hosted ResourceSpace tenants this call
    often returns HTTP 400 with `{"error": true, "error_note": ...}` even
    when the file is accepted (the preview generation step fails). We
    treat that case as non-fatal so the caller can trigger previews
    explicitly afterwards.
    """
    url = _build_signed_api_url(
        api_url=tenant["apiUrl"],
        username=username,
        session_key=session_key,
        params=params,
    )
    pinned_urls, host_headers, extensions = pin_request(url)
    try:
        with httpx.Client(
            timeout=httpx.Timeout(120.0, connect=5.0),
            trust_env=False,
            headers=_resourcespace_request_headers(integration),
        ) as client:
            response = _first_reachable(
                pinned_urls,
                lambda u: client.post(
                    u,
                    files={"file": (filename, file_bytes, content_type)},
                    headers=host_headers,
                    extensions=extensions,
                ),
            )
    except httpx.HTTPError as exc:
        raise ResourceSpaceError(
            "UPSTREAM_UNAVAILABLE",
            "ResourceSpace could not be reached.",
            502,
        ) from exc

    try:
        body = response.json()
    except ValueError:
        body = response.text

    # Treat HTTP 400 with an `error` JSON as preview-generation failure,
    # not upload failure: the file bytes are already stored.
    if response.status_code >= 400:
        if isinstance(body, dict) and body.get("error") is True:
            return {"uploaded": True, "previewError": body.get("error_note")}
        raise ResourceSpaceError(
            "UPSTREAM_REQUEST_FAILED",
            f"ResourceSpace upload returned HTTP {response.status_code}: {str(body)[:200]}",
            502,
        )

    return body


_EXPORT_EXT_MAP = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/svg+xml": "svg",
    "application/pdf": "pdf",
    "video/mp4": "mp4",
}


def _read_export_hop(
    client: httpx.Client,
    pinned_urls: list[str],
    host_headers: dict[str, str],
    extensions: dict[str, Any],
    max_bytes: int,
) -> dict[str, Any]:
    """Fetch one hop of the export download, trying each validated address for
    connection-level fallback. Returns a redirect marker or the read body."""
    last_exc: httpx.HTTPError | None = None
    for pinned_url in pinned_urls:
        try:
            with client.stream(
                "GET", pinned_url, headers=host_headers, extensions=extensions
            ) as response:
                if response.status_code in (301, 302, 303, 307, 308):
                    return {"redirect": True, "location": response.headers.get("location")}
                if response.status_code >= 400:
                    raise ResourceSpaceError(
                        "UPSTREAM_REQUEST_FAILED",
                        f"Export URL returned HTTP {response.status_code}",
                        502,
                    )
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        if int(content_length) > max_bytes:
                            raise ResourceSpaceError(
                                "INVALID_REQUEST",
                                f"Export exceeds CANVA_UPLOAD_MAX_BYTES ({max_bytes}).",
                                413,
                            )
                    except ValueError:
                        pass
                chunks: list[bytes] = []
                received = 0
                for chunk in response.iter_bytes():
                    received += len(chunk)
                    if received > max_bytes:
                        raise ResourceSpaceError(
                            "INVALID_REQUEST",
                            f"Export exceeds CANVA_UPLOAD_MAX_BYTES ({max_bytes}).",
                            413,
                        )
                    chunks.append(chunk)
                content_type = (
                    response.headers.get("content-type", "application/octet-stream")
                    .split(";")[0]
                    .strip()
                )
                return {"redirect": False, "body": b"".join(chunks), "contentType": content_type}
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last_exc = exc
    raise last_exc if last_exc is not None else httpx.ConnectError("no validated addresses")


def _download_bytes(url: str, config: AppConfig) -> tuple[bytes, str, str]:
    """Fetch a Canva-supplied export URL with SSRF + size protections.

    Each redirect hop is independently validated against the host allowlist and
    private-IP rules AND DNS-pinned to a validated address (the export URL is
    caller-controlled by any dam:write bearer and the allowlist is optional, so
    the connection must not be able to rebind between validation and connect).
    The response is streamed and capped at ``CANVA_UPLOAD_MAX_BYTES``.
    """
    max_bytes = config.upload.max_bytes
    redirects_remaining = 5
    current_url = url

    while True:
        _validate_export_url(current_url, config)
        pinned_urls, host_headers, extensions = pin_request(current_url)
        try:
            # trust_env=False so an env HTTPS_PROXY cannot CONNECT-tunnel past the
            # pin and verify TLS against the pinned IP instead of the host.
            with httpx.Client(
                timeout=httpx.Timeout(60.0, connect=5.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                hop = _read_export_hop(client, pinned_urls, host_headers, extensions, max_bytes)
        except httpx.HTTPError as exc:
            raise ResourceSpaceError(
                "UPSTREAM_UNAVAILABLE",
                f"Failed to download export: {exc}",
                502,
            ) from exc

        if hop["redirect"]:
            if redirects_remaining <= 0:
                raise ResourceSpaceError(
                    "UPSTREAM_REQUEST_FAILED",
                    "Too many redirects fetching export URL.",
                    502,
                )
            next_url = hop["location"]
            if not next_url:
                raise ResourceSpaceError(
                    "UPSTREAM_REQUEST_FAILED",
                    "Redirect missing Location header.",
                    502,
                )
            # Resolve relative redirects against the prior hop; the next loop
            # iteration re-validates AND re-pins the resolved URL.
            current_url = str(httpx.URL(current_url).join(next_url))
            redirects_remaining -= 1
            continue

        content_type = hop["contentType"]
        ext = _EXPORT_EXT_MAP.get(content_type, "bin")
        filename = f"canva-export.{ext}"
        return hop["body"], filename, content_type


def _upload_live_resource(
    session: dict[str, Any],
    *,
    config: AppConfig,
    collection_ref: str,
    source_url: str,
    title: str | None,
) -> dict[str, Any]:
    tenant = session["tenant"]
    username = session["user"]["username"]
    session_key = session["upstream"]["sessionKey"]
    integration = _broker_integration_from_session(session)

    new_ref = _call_live_api(
        tenant=tenant,
        username=username,
        session_key=session_key,
        integration=integration,
        params={
            "function": "create_resource",
            "resource_type": 1,
            "archive": 0,
        },
    )
    if new_ref in (False, "false", "", None) or (
        isinstance(new_ref, str) and not new_ref.strip().lstrip("-").isdigit()
    ):
        raise ResourceSpaceError(
            "UPLOAD_FAILED",
            f"ResourceSpace create_resource returned: {new_ref!r}",
            502,
        )
    ref_str = str(new_ref).strip()

    file_bytes, filename, content_type = _download_bytes(source_url, config)
    extension = filename.rsplit(".", 1)[-1] if "." in filename else "jpg"

    upload_result = _post_multipart_live_api(
        tenant=tenant,
        username=username,
        session_key=session_key,
        params={
            "function": "upload_multipart",
            "ref": ref_str,
            "no_exif": 0,
            "revert": 0,
        },
        file_bytes=file_bytes,
        filename=filename,
        content_type=content_type,
        integration=integration,
    )
    if upload_result in (False, "false", "", None):
        raise ResourceSpaceError(
            "UPLOAD_FAILED",
            f"ResourceSpace upload_multipart returned: {upload_result!r} (resource ref {ref_str})",
            502,
        )

    # Hosted ResourceSpace tiers often can't generate previews server
    # side (no ImageMagick available), so `create_previews` silently
    # no-ops. Generate a JPEG preview locally and upload it via
    # upload_multipart with previewonly=1 — that sets has_image=1 and
    # stores thumbnail/preview variants without needing ImageMagick.
    try:
        preview_bytes = _build_jpeg_preview(
            file_bytes,
            max_image_pixels=config.upload.max_image_pixels,
        )
    except _PreviewGenerationError:
        preview_bytes = None

    if preview_bytes:
        try:
            _post_multipart_live_api(
                tenant=tenant,
                username=username,
                session_key=session_key,
                params={
                    "function": "upload_multipart",
                    "ref": ref_str,
                    "no_exif": 1,
                    "revert": 0,
                    "previewonly": 1,
                },
                file_bytes=preview_bytes,
                filename="preview.jpg",
                content_type="image/jpeg",
                integration=integration,
            )
        except ResourceSpaceError:
            pass

    if title:
        _call_live_api(
            tenant=tenant,
            username=username,
            session_key=session_key,
            integration=integration,
            params={
                "function": "update_field",
                "resource": ref_str,
                "field": 8,
                "value": title,
            },
        )

    link_result = _call_live_api(
        tenant=tenant,
        username=username,
        session_key=session_key,
        integration=integration,
        params={
            "function": "add_resource_to_collection",
            "resource": ref_str,
            "collection": collection_ref,
        },
    )
    if link_result in (False, "false"):
        raise ResourceSpaceError(
            "LINK_FAILED",
            "Resource was created but could not be added to the collection.",
            502,
        )

    return {"id": ref_str}
