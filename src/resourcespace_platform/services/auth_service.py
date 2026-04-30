"""OAuth authorization-code + PKCE + refresh token bookkeeping.

Tokens are issued opaquely and bound to a ResourceSpace session (tenant + user).
The Canva OAuth provider flow uses PKCE with S256 challenges.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any

from ..config import AppConfig
from .json_store import JsonStore
from .resourcespace import ResourceSpaceService


def _now_ms() -> int:
    return int(time.time() * 1000)


def _random_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def _sha256_b64url(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _prune_expired(
    state: dict[str, dict[str, Any]],
    now: int | None = None,
    *,
    refresh_grace_ms: int = 0,
) -> None:
    current = now if now is not None else _now_ms()

    for code, record in list(state["authorizationCodes"].items()):
        if record["expiresAt"] <= current:
            del state["authorizationCodes"][code]

    for token, record in list(state["accessTokens"].items()):
        if record["expiresAt"] <= current or record.get("revokedAt"):
            del state["accessTokens"][token]

    for token, record in list(state["refreshTokens"].items()):
        revoked_at = record.get("revokedAt")
        expires_at = record.get("expiresAt")
        if revoked_at and current - revoked_at > refresh_grace_ms:
            del state["refreshTokens"][token]
            continue
        if expires_at and expires_at <= current:
            del state["refreshTokens"][token]

    for grant_id, record in list(state["assetGrants"].items()):
        if record["expiresAt"] <= current:
            del state["assetGrants"][grant_id]


class AuthService:
    def __init__(
        self,
        *,
        config: AppConfig,
        store: JsonStore,
        resourcespace_service: ResourceSpaceService,
    ) -> None:
        self._config = config
        self._store = store
        self._resourcespace_service = resourcespace_service
        self._refresh_grace_ms = config.oauth.refresh_grace_seconds * 1000

    def _prune(self, state: dict[str, dict[str, Any]]) -> None:
        _prune_expired(state, refresh_grace_ms=self._refresh_grace_ms)

    def begin_authorization(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str = "",
        code_challenge: str | None,
        code_challenge_method: str | None,
        tenant_base_url: str | None,
        username: str,
        password: str,
    ) -> str:
        session = self._resourcespace_service.authenticate(
            tenant_base_url=tenant_base_url,
            username=username,
            password=password,
        )

        def _updater(state: dict[str, dict[str, Any]]) -> str:
            self._prune(state)
            code = _random_token("code")
            state["authorizationCodes"][code] = {
                "code": code,
                "clientId": client_id,
                "redirectUri": redirect_uri,
                "scope": scope,
                "codeChallenge": code_challenge,
                "codeChallengeMethod": code_challenge_method or "S256",
                "session": session,
                "expiresAt": _now_ms() + self._config.oauth.auth_code_ttl_seconds * 1000,
            }
            return code

        return self._store.update(_updater)

    def _create_token_pair(
        self,
        *,
        session: dict[str, Any],
        scope: str,
        client_id: str,
        rotate_refresh_token: bool = True,
        existing_refresh_token: str | None = None,
    ) -> dict[str, Any]:
        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
            self._prune(state)
            access_token = _random_token("at")
            access_expires_at = _now_ms() + self._config.oauth.token_ttl_seconds * 1000
            refresh_token = _random_token("rt") if rotate_refresh_token else existing_refresh_token

            state["accessTokens"][access_token] = {
                "accessToken": access_token,
                "clientId": client_id,
                "scope": scope,
                "session": session,
                "expiresAt": access_expires_at,
                "createdAt": _now_ms(),
            }

            if rotate_refresh_token and refresh_token:
                state["refreshTokens"][refresh_token] = {
                    "refreshToken": refresh_token,
                    "clientId": client_id,
                    "scope": scope,
                    "session": session,
                    "createdAt": _now_ms(),
                    "expiresAt": _now_ms() + 30 * 24 * 60 * 60 * 1000,
                    "revokedAt": None,
                }

            return {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": self._config.oauth.token_ttl_seconds,
                "refresh_token": refresh_token,
                "scope": scope,
            }

        return self._store.update(_updater)

    def exchange_authorization_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code: str,
        code_verifier: str | None,
    ) -> dict[str, Any]:
        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
            self._prune(state)
            record = state["authorizationCodes"].get(code)
            if not record:
                return {"error": "invalid_grant", "description": "Authorization code not found."}
            del state["authorizationCodes"][code]
            if record["clientId"] != client_id or record["redirectUri"] != redirect_uri:
                return {"error": "invalid_grant", "description": "Client binding mismatch."}
            if not record.get("codeChallenge") or not code_verifier:
                return {"error": "invalid_request", "description": "PKCE code verifier is required."}
            method = record.get("codeChallengeMethod") or "S256"
            if method != "S256":
                return {"error": "invalid_request", "description": "Only S256 PKCE is supported."}
            expected = _sha256_b64url(code_verifier)
            if expected != record["codeChallenge"]:
                return {"error": "invalid_grant", "description": "PKCE verification failed."}
            return {"ok": True, "session": record["session"], "scope": record["scope"]}

        result = self._store.update(_updater)
        if result.get("error"):
            return result
        return self._create_token_pair(
            session=result["session"],
            scope=result["scope"],
            client_id=client_id,
        )

    def refresh_access_token(self, *, client_id: str, refresh_token: str) -> dict[str, Any]:
        # Rotate the refresh token on every use. The previous token stays
        # valid for `OAUTH_REFRESH_GRACE_SECONDS` so that two near-simultaneous
        # refresh attempts (e.g. two tabs) don't cause one to fail.
        grace_ms = self._config.oauth.refresh_grace_seconds * 1000

        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
            _prune_expired(state, refresh_grace_ms=grace_ms)
            record = state["refreshTokens"].get(refresh_token)
            if not record or record["clientId"] != client_id:
                return {"error": "invalid_grant", "description": "Refresh token not found."}
            # Mark the old refresh token revoked-with-grace so a duplicate
            # call within `grace_ms` still resolves the session.
            if not record.get("revokedAt"):
                record["revokedAt"] = _now_ms()
            return {"ok": True, "session": record["session"], "scope": record["scope"]}

        result = self._store.update(_updater)
        if result.get("error"):
            return result
        return self._create_token_pair(
            session=result["session"],
            scope=result["scope"],
            client_id=client_id,
        )

    def read_access_token(self, token: str) -> dict[str, Any] | None:
        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
            self._prune(state)
            return state["accessTokens"].get(token)

        return self._store.update(_updater)

    def revoke_token(self, token: str) -> bool:
        def _updater(state: dict[str, dict[str, Any]]) -> bool:
            self._prune(state)
            if token in state["accessTokens"]:
                state["accessTokens"][token]["revokedAt"] = _now_ms()
                del state["accessTokens"][token]
                return True
            if token in state["refreshTokens"]:
                state["refreshTokens"][token]["revokedAt"] = _now_ms()
                return True
            return False

        return self._store.update(_updater)

    def revoke_tokens_for_user(self, *, user_id: str, tenant_id: str) -> None:
        def _updater(state: dict[str, dict[str, Any]]) -> None:
            self._prune(state)
            now = _now_ms()
            for record in state["accessTokens"].values():
                session = record["session"]
                if session["user"]["id"] == user_id and session["tenant"]["id"] == tenant_id:
                    record["revokedAt"] = now
            for record in state["refreshTokens"].values():
                session = record["session"]
                if session["user"]["id"] == user_id and session["tenant"]["id"] == tenant_id:
                    record["revokedAt"] = now
            for record in state["assetGrants"].values():
                if record.get("userId") == user_id and record.get("tenantId") == tenant_id:
                    record["expiresAt"] = 0

        self._store.update(_updater)

    def read_user_info_from_access_token(self, token: str) -> dict[str, Any] | None:
        record = self.read_access_token(token)
        if not record:
            return None
        summary = self._resourcespace_service.get_session_summary(record["session"])
        return {
            "sub": summary["user"]["id"],
            "preferred_username": summary["user"]["username"],
            "name": summary["user"]["displayName"],
            "tenant_id": summary["tenant"]["id"],
            "tenant_slug": summary["tenant"]["slug"],
            "tenant_name": summary["tenant"]["name"],
            "role": summary["user"]["role"],
            "scope": record["scope"],
        }

    def get_stats(self) -> dict[str, int]:
        state = self._store.read()
        self._prune(state)
        return {
            "authorizationCodeCount": len(state["authorizationCodes"]),
            "accessTokenCount": len(state["accessTokens"]),
            "refreshTokenCount": len(state["refreshTokens"]),
            "assetGrantCount": len(state["assetGrants"]),
        }


def create_auth_service(
    *,
    config: AppConfig,
    store: JsonStore,
    resourcespace_service: ResourceSpaceService,
) -> AuthService:
    return AuthService(
        config=config,
        store=store,
        resourcespace_service=resourcespace_service,
    )
