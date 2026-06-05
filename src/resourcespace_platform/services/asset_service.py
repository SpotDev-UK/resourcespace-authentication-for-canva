"""Short-lived signed-URL grants for asset delivery.

Grants are HMAC-signed (secret lives in ASSET_SIGNING_SECRET) and expire after
`SIGNED_URL_TTL_SECONDS`. Two grant paths:

- `/public/assets/:grantId`  — previews/thumbnails
- `/signed/assets/:grantId`  — full download for Canva import
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx

from ..config import AppConfig
from ..data import fixture_data as fixture
from .json_store import JsonStore
from .resourcespace._helpers import _broker_integration_from_session, _resourcespace_request_headers


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
            return 200, body, combined_headers

        try:
            async with httpx.AsyncClient(
                timeout=30.0,
                headers=_resourcespace_request_headers(grant.get("integration")),
            ) as client:
                upstream = await client.get(source["url"])
        except httpx.HTTPError:
            return None
        if upstream.status_code >= 400:
            return None
        body = upstream.content
        combined_headers["Content-Type"] = (
            grant.get("mimeType")
            or upstream.headers.get("content-type")
            or "application/octet-stream"
        )
        filename = grant.get("filename")
        if filename:
            safe = filename.replace('"', "")
            combined_headers["Content-Disposition"] = f'inline; filename="{safe}"'
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
