"""Short-lived signed-URL grants for asset delivery.

Grants are HMAC-signed (secret lives in ASSET_SIGNING_SECRET) and expire after
`SIGNED_URL_TTL_SECONDS`. Two grant paths:

- `/public/assets/:grantId`  — previews/thumbnails
- `/signed/assets/:grantId`  — full download for Canva import
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from ..config import AppConfig
from ..data import fixture_data as fixture
from .json_store import JsonStore
from .resourcespace._helpers import (
    ResourceSpaceError,
    _broker_integration_from_session,
    _resourcespace_request_headers,
    pin_request,
)

# The CONNECT + response-header race across a host's validated addresses is
# bounded by one hard deadline; candidates are attempted concurrently with a
# short start stagger (Happy-Eyeballs style) so a black-holed address neither
# blocks the worker nor delays fallback. Only the winning connection's body is
# then streamed (bounded memory), OUTSIDE the connect deadline, with its own
# read-idle timeout.
_PROXY_CONNECT_DEADLINE_SECONDS = 8.0
_PROXY_STAGGER_SECONDS = 0.25
_PROXY_PER_ADDRESS_CONNECT_SECONDS = 5.0
_PROXY_READ_TIMEOUT_SECONDS = 30.0


async def _safe_aclose(stream_cm: Any) -> None:
    with contextlib.suppress(Exception):
        await stream_cm.__aexit__(None, None, None)


async def _open_pinned_stream(
    client: httpx.AsyncClient,
    url: str,
    host_headers: dict[str, str],
    extensions: dict[str, Any],
) -> tuple[Any, httpx.Response]:
    """Connect and read the response headers only (not the body). Returns the
    open stream context manager and its response so the caller can either read
    the body or close it. Raises ``httpx.ConnectError``/``ConnectTimeout`` on a
    connection failure so the racer can fall back."""
    timeout = httpx.Timeout(
        _PROXY_READ_TIMEOUT_SECONDS, connect=_PROXY_PER_ADDRESS_CONNECT_SECONDS
    )
    stream_cm = client.stream(
        "GET", url, headers=host_headers, extensions=extensions, timeout=timeout
    )
    response = await stream_cm.__aenter__()
    return stream_cm, response


async def _race_pinned_connection(
    client: httpx.AsyncClient,
    pinned_urls: list[str],
    host_headers: dict[str, str],
    extensions: dict[str, Any],
) -> tuple[Any, httpx.Response] | None:
    """Open connections to the pinned addresses concurrently (staggered) under
    one hard connect deadline. Returns the first (stream_cm, response) with an
    acceptable (<400) status, or None. Losing/errored streams are closed and
    pending attempts cancelled; the winner is left open for the caller to read.
    A connected-but-unusable status (>=400) gives up (other addresses serve the
    same resource)."""

    async def _attempt(index: int, url: str) -> tuple[Any, httpx.Response]:
        if index:
            await asyncio.sleep(index * _PROXY_STAGGER_SECONDS)
        return await _open_pinned_stream(client, url, host_headers, extensions)

    tasks = [asyncio.create_task(_attempt(i, u)) for i, u in enumerate(pinned_urls)]
    index_of = {task: index for index, task in enumerate(tasks)}
    winner: tuple[Any, httpx.Response] | None = None
    # An unexpected (non-transport) error is captured and re-raised OUTSIDE the
    # timeout scope: raising it inside would let the deadline's `except
    # TimeoutError` swallow a re-raised built-in TimeoutError and mask the bug.
    unexpected: BaseException | None = None
    try:
        async with asyncio.timeout(_PROXY_CONNECT_DEADLINE_SECONDS):
            pending = set(tasks)
            give_up = False
            while pending and winner is None and not give_up and unexpected is None:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                # Process a completed batch deterministically: an acceptable
                # (<400) response always wins over a bad/errored one that
                # completes in the same tick, and the lowest-ordered acceptable
                # candidate is chosen (set iteration order is irrelevant). Only
                # give up if a batch has no acceptable response but does have a
                # bad status (other addresses serve the same resource). Bad/extra
                # streams are closed in the finally.
                accepted: list[tuple[int, Any, httpx.Response]] = []
                saw_reject = False
                for task in done:
                    exc = task.exception()
                    if exc is None:
                        stream_cm, response = task.result()
                        if response.status_code < 400:
                            accepted.append((index_of[task], stream_cm, response))
                        else:
                            # A genuine HTTP error status: authoritative.
                            saw_reject = True
                    elif isinstance(exc, httpx.TransportError):
                        # Address-specific transport failure (ConnectError,
                        # ReadTimeout, WriteError, RemoteProtocolError, ...):
                        # ignore it and try the remaining addresses.
                        pass
                    elif unexpected is None:
                        # Unexpected (programming/config) error: capture the
                        # first and surface it after the timeout scope.
                        unexpected = exc
                if accepted:
                    accepted.sort(key=lambda item: item[0])
                    winner = (accepted[0][1], accepted[0][2])
                elif saw_reject:
                    give_up = True
    except TimeoutError:
        pass  # the connect deadline expired; treat as no reachable address
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, tuple) and len(result) == 2:
                stream_cm, _resp = result
                if winner is None or stream_cm is not winner[0]:
                    await _safe_aclose(stream_cm)
    # A genuine success still wins; otherwise surface the unexpected error.
    if winner is None and unexpected is not None:
        raise unexpected
    return winner


async def _race_pinned_fetch(
    pinned_urls: list[str],
    host_headers: dict[str, str],
    extensions: dict[str, Any],
    max_bytes: int,
    integration: str | None,
) -> tuple[bytes, str | None] | None:
    """Race the pinned addresses to an acceptable response, then stream ONLY the
    winner's body (bounded memory) with a read-idle timeout, outside the connect
    deadline. Returns (body, content-type) or None.

    follow_redirects is pinned False (a redirect could pivot to an unvalidated
    host) and trust_env False (an env proxy would CONNECT-tunnel past the pin).
    """
    async with httpx.AsyncClient(
        follow_redirects=False,
        trust_env=False,
        headers=_resourcespace_request_headers(integration),
    ) as client:
        winner = await _race_pinned_connection(
            client, pinned_urls, host_headers, extensions
        )
        if winner is None:
            return None
        stream_cm, response = winner
        try:
            declared = response.headers.get("content-length")
            if declared is not None:
                try:
                    if int(declared) > max_bytes:
                        return None
                except ValueError:
                    pass
            chunks: list[bytes] = []
            received = 0
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > max_bytes:
                    return None  # abort without returning partial content
                chunks.append(chunk)
            return b"".join(chunks), response.headers.get("content-type")
        except httpx.HTTPError:
            return None
        finally:
            await _safe_aclose(stream_cm)


def _is_svg_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    return content_type.split(";", 1)[0].strip().lower() == "image/svg+xml"


def _harden_asset_response_headers(
    headers: dict[str, str],
    *,
    content_type: str,
    filename: str | None,
    from_proxy: bool,
) -> None:
    headers["X-Content-Type-Options"] = "nosniff"
    headers["Content-Security-Policy"] = "default-src 'none'; sandbox"
    if from_proxy and _is_svg_content_type(content_type):
        headers["Content-Type"] = "application/octet-stream"
        headers["Content-Disposition"] = _attachment_content_disposition(filename or "download.svg")


def _sanitized_filename_parts(filename: str) -> tuple[str, str]:
    cleaned = "".join(ch for ch in filename if ord(ch) >= 32 and ord(ch) != 127)
    ascii_fallback = cleaned.encode("ascii", "ignore").decode("ascii").replace('"', "").strip()
    if not ascii_fallback:
        ascii_fallback = "download"
    encoded = quote(cleaned, safe="")
    return ascii_fallback, encoded


def _content_disposition(filename: str) -> str:
    """Build a safe inline Content-Disposition value.

    Strips control characters (CR/LF included) to block response-header
    injection, and emits an RFC 5987 ``filename*`` for non-ASCII names
    alongside an ASCII-only ``filename`` fallback (a raw non-latin-1 value
    in a header raises at the ASGI layer).
    """
    ascii_fallback, encoded = _sanitized_filename_parts(filename)
    return f"inline; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"


def _attachment_content_disposition(filename: str) -> str:
    ascii_fallback, encoded = _sanitized_filename_parts(filename)
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{encoded}"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _random_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def _create_signature(*, grant_id: str, expires_at: int, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{grant_id}:{expires_at}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _prune_expired_grants(state: dict[str, dict[str, Any]], now: int | None = None) -> None:
    current = now if now is not None else _now_ms()
    for grant_id, record in list(state["assetGrants"].items()):
        if record["expiresAt"] <= current:
            del state["assetGrants"][grant_id]


class AssetService:
    def __init__(self, *, config: AppConfig, store: JsonStore) -> None:
        self._config = config
        self._store = store

    def _create_grant(
        self,
        *,
        path_prefix: str,
        session: dict[str, Any],
        source: dict[str, Any],
        mime_type: str | None,
        filename: str | None,
    ) -> dict[str, Any]:
        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
            _prune_expired_grants(state)
            grant_id = _random_id("grant")
            expires_at = _now_ms() + self._config.oauth.signed_url_ttl_seconds * 1000
            signature = _create_signature(
                grant_id=grant_id,
                expires_at=expires_at,
                secret=self._config.signing.asset_secret,
            )
            state["assetGrants"][grant_id] = {
                "grantId": grant_id,
                "userId": session["user"]["id"],
                "tenantId": session["tenant"]["id"],
                "expiresAt": expires_at,
                "source": source,
                "integration": _broker_integration_from_session(session),
                "mimeType": mime_type,
                "filename": filename,
            }

            query = urlencode({"expires": str(expires_at), "sig": signature})
            return {
                "grantId": grant_id,
                "url": f"{self._config.base_url}{path_prefix}/{grant_id}?{query}",
                "expiresAt": _iso_from_ms(expires_at),
            }

        return self._store.update(_updater)

    def create_preview_grant(
        self,
        *,
        session: dict[str, Any],
        source: dict[str, Any],
        mime_type: str | None,
        filename: str | None,
    ) -> dict[str, Any]:
        return self._create_grant(
            path_prefix="/public/assets",
            session=session,
            source=source,
            mime_type=mime_type,
            filename=filename,
        )

    def create_download_grant(
        self,
        *,
        session: dict[str, Any],
        source: dict[str, Any],
        mime_type: str | None,
        filename: str | None,
    ) -> dict[str, Any]:
        return self._create_grant(
            path_prefix="/signed/assets",
            session=session,
            source=source,
            mime_type=mime_type,
            filename=filename,
        )

    def verify_grant(
        self, *, grant_id: str | None, expires_at: str | None, signature: str | None
    ) -> dict[str, Any]:
        if not grant_id or not expires_at or not signature:
            return {"ok": False, "reason": "missing_signature"}

        try:
            expiry = int(expires_at)
        except (TypeError, ValueError):
            return {"ok": False, "reason": "expired"}

        if expiry < _now_ms():
            return {"ok": False, "reason": "expired"}

        expected = _create_signature(
            grant_id=grant_id,
            expires_at=expiry,
            secret=self._config.signing.asset_secret,
        )
        if not hmac.compare_digest(expected, signature):
            return {"ok": False, "reason": "invalid_signature"}

        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
            _prune_expired_grants(state)
            return state["assetGrants"].get(grant_id)

        grant = self._store.update(_updater)
        if not grant or grant["expiresAt"] < _now_ms():
            return {"ok": False, "reason": "expired"}

        return {"ok": True, "grant": grant}

    async def build_grant_response(
        self, verification: dict[str, Any], headers: dict[str, str] | None = None
    ) -> tuple[int, bytes | bytes, dict[str, str]] | None:
        """Return (status, body-bytes, headers) for a verified grant.

        For `kind=fixture` sources we render an SVG inline. For `kind=proxy`
        sources we pull bytes from ResourceSpace and return them.
        Returns `None` if the grant cannot be fulfilled.
        """
        if not verification.get("ok"):
            return None
        grant = verification["grant"]
        source = grant["source"]
        combined_headers = {
            "Cache-Control": "private, max-age=60",
            **(headers or {}),
        }

        if source["kind"] == "fixture":
            asset = fixture.get_asset_by_id(source["assetId"])
            if not asset:
                return None
            body = fixture.render_fixture_svg(asset, source.get("variant", "preview")).encode(
                "utf-8"
            )
            combined_headers["Content-Type"] = grant.get("mimeType") or "image/svg+xml; charset=utf-8"
            _harden_asset_response_headers(
                combined_headers,
                content_type=combined_headers["Content-Type"],
                filename=grant.get("filename"),
                from_proxy=False,
            )
            return 200, body, combined_headers

        # SSRF guard + DNS pin. Canonicalises the host (UTS46), checks the
        # optional allowlist, and resolves + validates + pins the addresses, all
        # on the exact host httpx would connect to. Run OFF the event loop: the
        # blocking getaddrinfo must not stall the Uvicorn worker.
        try:
            pinned_urls, host_headers, extensions = await asyncio.to_thread(
                pin_request,
                source["url"],
                allowed_hosts=self._config.resource_space.asset_allowed_hosts,
            )
        except ResourceSpaceError:
            return None

        fetched = await _race_pinned_fetch(
            pinned_urls,
            host_headers,
            extensions,
            self._config.resource_space.asset_proxy_max_bytes,
            grant.get("integration"),
        )
        if fetched is None:
            return None
        body, content_type_header = fetched
        combined_headers["Content-Type"] = (
            grant.get("mimeType")
            or content_type_header
            or "application/octet-stream"
        )
        filename = grant.get("filename")
        if filename:
            combined_headers["Content-Disposition"] = _content_disposition(filename)
        _harden_asset_response_headers(
            combined_headers,
            content_type=combined_headers["Content-Type"],
            filename=filename,
            from_proxy=True,
        )
        return 200, body, combined_headers


def _iso_from_ms(ms: int) -> str:
    from datetime import datetime, timezone

    return (
        datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def create_asset_service(*, config: AppConfig, store: JsonStore) -> AssetService:
    return AssetService(config=config, store=store)
