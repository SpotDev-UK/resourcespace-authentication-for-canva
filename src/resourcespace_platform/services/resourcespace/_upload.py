"""Upload / preview-generation helpers for live ResourceSpace tenants."""
from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

from ...config import AppConfig
from ._helpers import (
    ResourceSpaceError,
    _broker_integration_from_session,
    _build_signed_api_url,
    _resourcespace_request_headers,
)
from ._live_backend import _call_live_api


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


def _is_private_ip(host: str) -> bool:
    """Return True if `host` resolves to any loopback / private / link-local
    address. Used to block SSRF against the broker's internal network."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        # Hostname doesn't resolve; treat as unsafe rather than risk a TOCTOU
        # where it resolves to an internal address mid-request.
        return True
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
    return False


def _validate_export_url(url: str, config: AppConfig) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ResourceSpaceError(
            "INVALID_REQUEST",
            "Export URLs must use https.",
            400,
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise ResourceSpaceError(
            "INVALID_REQUEST",
            "Export URL is missing a hostname.",
            400,
        )

    allowed_hosts = [h.lower() for h in config.upload.allowed_hosts]
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
    try:
        with httpx.Client(
            timeout=120.0,
            headers=_resourcespace_request_headers(integration),
        ) as client:
            response = client.post(
                url,
                files={"file": (filename, file_bytes, content_type)},
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


def _download_bytes(url: str, config: AppConfig) -> tuple[bytes, str, str]:
    """Fetch a Canva-supplied export URL with SSRF + size protections.

    Each redirect hop is independently validated against the host allowlist
    and private-IP rules; the response is streamed and capped at
    ``CANVA_UPLOAD_MAX_BYTES`` to avoid memory exhaustion.
    """
    _validate_export_url(url, config)
    max_bytes = config.upload.max_bytes
    redirects_remaining = 5
    current_url = url

    while True:
        try:
            with httpx.Client(timeout=60.0, follow_redirects=False) as client:
                with client.stream("GET", current_url) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        if redirects_remaining <= 0:
                            raise ResourceSpaceError(
                                "UPSTREAM_REQUEST_FAILED",
                                "Too many redirects fetching export URL.",
                                502,
                            )
                        next_url = response.headers.get("location")
                        if not next_url:
                            raise ResourceSpaceError(
                                "UPSTREAM_REQUEST_FAILED",
                                "Redirect missing Location header.",
                                502,
                            )
                        # Resolve relative redirects against the prior hop, then
                        # re-validate. This is the SSRF-critical step: a trusted
                        # host that redirects to localhost is still SSRF.
                        resolved = str(httpx.URL(current_url).join(next_url))
                        _validate_export_url(resolved, config)
                        current_url = resolved
                        redirects_remaining -= 1
                        continue

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
        except httpx.HTTPError as exc:
            raise ResourceSpaceError(
                "UPSTREAM_UNAVAILABLE",
                f"Failed to download export: {exc}",
                502,
            ) from exc

        ext_map = {
            "image/jpeg": "jpg",
            "image/png": "png",
            "image/webp": "webp",
            "image/gif": "gif",
            "image/svg+xml": "svg",
            "application/pdf": "pdf",
            "video/mp4": "mp4",
        }
        ext = ext_map.get(content_type, "bin")
        filename = f"canva-export.{ext}"
        return b"".join(chunks), filename, content_type


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
