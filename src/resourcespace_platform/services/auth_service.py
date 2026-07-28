"""OAuth authorization-code + PKCE + refresh token bookkeeping.

Tokens are issued opaquely and bound to a ResourceSpace session (tenant + user).
The Canva OAuth provider flow uses PKCE with S256 challenges.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import secrets
import time
from typing import Any

from .. import logger as log
from ..config import AppConfig
from .field_crypto import FieldCipher, FieldDecryptError
from .json_store import JsonStore
from .resourcespace import ResourceSpaceError, ResourceSpaceService


# Upper bound on concurrently outstanding pending SSO handoff states. Prevents
# an unauthenticated flood of /oauth/authorise?auth_method=sso requests from
# growing the JSON store without limit (each transaction rewrites the file).
_MAX_PENDING_SSO_STATES = 2000


def _max_pending_sso_states_per_source(config: AppConfig) -> int:
    """Cap outstanding handoff states per initiator in line with ingress limits."""
    window_s = config.rate_limit.window_ms / 1000
    pending_window_s = config.resource_space.sso_pending_ttl_seconds
    from_rate = int(config.rate_limit.max_requests * pending_window_s / window_s)
    return max(10, min(from_rate, _MAX_PENDING_SSO_STATES // 10))


def _is_active_pending_sso_state(record: dict[str, Any], now: int) -> bool:
    """Return True for an unused handoff state that has not yet expired."""
    return record.get("usedAt") is None and record.get("expiresAt", 0) > now


def _now_ms() -> int:
    return int(time.time() * 1000)


def _random_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def _sha256_b64url(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _integration_for_client_id(config: AppConfig, client_id: str) -> str | None:
    client = config.oauth.clients.get(client_id)
    return client.integration if client else None


def _is_configured_client(config: AppConfig, client_id: str) -> bool:
    return client_id in config.oauth.clients


def _stamp_broker_session_metadata(
    session: dict[str, Any],
    *,
    client_id: str,
    integration: str | None,
) -> dict[str, Any]:
    existing_broker = session.get("broker")
    broker = existing_broker.copy() if isinstance(existing_broker, dict) else {}
    broker["clientId"] = client_id
    if integration:
        broker["integration"] = integration
    else:
        broker.pop("integration", None)
    return {**session, "broker": broker}


def _stamp_token_record_metadata(config: AppConfig, record: dict[str, Any]) -> bool:
    client_id = str(record.get("clientId") or "")
    if not _is_configured_client(config, client_id):
        return False
    integration = _integration_for_client_id(config, client_id)
    record["integration"] = integration
    record["session"] = _stamp_broker_session_metadata(
        record["session"],
        client_id=client_id,
        integration=integration,
    )
    return True


def _write_token_pair_to_state(
    service: "AuthService",
    state: dict[str, dict[str, Any]],
    *,
    session: dict[str, Any],
    scope: str,
    client_id: str,
    rotate_refresh_token: bool = True,
    existing_refresh_token: str | None = None,
) -> dict[str, Any]:
    """Mint access/refresh tokens into ``state`` and return the OAuth response body."""
    access_token = _random_token("at")
    access_expires_at = _now_ms() + service._config.oauth.token_ttl_seconds * 1000
    refresh_token = _random_token("rt") if rotate_refresh_token else existing_refresh_token
    integration = _integration_for_client_id(service._config, client_id)
    session_with_metadata = _stamp_broker_session_metadata(
        session,
        client_id=client_id,
        integration=integration,
    )
    session_with_metadata = service._seal_session(session_with_metadata)

    state["accessTokens"][access_token] = {
        "accessToken": access_token,
        "clientId": client_id,
        "scope": scope,
        "integration": integration,
        "session": session_with_metadata,
        "expiresAt": access_expires_at,
        "createdAt": _now_ms(),
    }

    if rotate_refresh_token and refresh_token:
        state["refreshTokens"][refresh_token] = {
            "refreshToken": refresh_token,
            "clientId": client_id,
            "scope": scope,
            "integration": integration,
            "session": session_with_metadata,
            "createdAt": _now_ms(),
            "expiresAt": _now_ms() + service._config.oauth.refresh_token_ttl_seconds * 1000,
            "revokedAt": None,
        }

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": service._config.oauth.token_ttl_seconds,
        "refresh_token": refresh_token,
        "scope": scope,
    }


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

    # Pending SSO states use tombstone retention: a used or expired record is
    # kept until purgeAt (= expiresAt + replay retention) so the callback can
    # distinguish a replay/expiry from an unknown state. Prune on purgeAt, NOT
    # expiresAt, so those tombstones survive long enough to be classified.
    for handoff_state, record in list(state.get("pendingSsoStates", {}).items()):
        if record.get("purgeAt", 0) <= current:
            del state["pendingSsoStates"][handoff_state]


class AuthService:
    def __init__(
        self,
        *,
        config: AppConfig,
        store: JsonStore,
        resourcespace_service: ResourceSpaceService,
        field_cipher: FieldCipher,
    ) -> None:
        self._config = config
        self._store = store
        self._resourcespace_service = resourcespace_service
        self._field_cipher = field_cipher
        self._refresh_grace_ms = config.oauth.refresh_grace_seconds * 1000

    def _seal_session(self, session: dict[str, Any]) -> dict[str, Any]:
        sealed = copy.deepcopy(session)
        upstream = sealed.get("upstream")
        if isinstance(upstream, dict) and upstream.get("sessionKey"):
            upstream["sessionKey"] = self._field_cipher.seal(upstream["sessionKey"])
        user = sealed.get("user")
        if isinstance(user, dict) and user.get("email"):
            user["email"] = self._field_cipher.seal(user["email"])
        return sealed

    def _open_session_dict(self, session: dict[str, Any]) -> dict[str, Any]:
        opened = copy.deepcopy(session)
        upstream = opened.get("upstream")
        if isinstance(upstream, dict) and upstream.get("sessionKey"):
            upstream["sessionKey"] = self._field_cipher.open(upstream["sessionKey"])
        user = opened.get("user")
        if isinstance(user, dict) and user.get("email"):
            user["email"] = self._field_cipher.open(user["email"])
        return opened

    def _open_session(self, record: dict[str, Any]) -> dict[str, Any] | None:
        session = record.get("session")
        if not isinstance(session, dict):
            return record
        opened_session = self._try_open_session_dict(session, bucket="accessTokens")
        if opened_session is None:
            return None
        opened = dict(record)
        opened["session"] = opened_session
        return opened

    def _try_open_session_dict(
        self, session: dict[str, Any], *, bucket: str
    ) -> dict[str, Any] | None:
        try:
            return self._open_session_dict(session)
        except FieldDecryptError:
            log.warn("store_decrypt_failed", {"bucket": bucket})
            return None

    def prune(self) -> None:
        self._store.update_strict(self._prune)

    def _prune(self, state: dict[str, dict[str, Any]]) -> None:
        _prune_expired(state, refresh_grace_ms=self._refresh_grace_ms)

    def _mint_authorization_code(
        self,
        state: dict[str, dict[str, Any]],
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
        session: dict[str, Any],
    ) -> str:
        """Store a fresh authorization code inside an open store transaction.

        Shared by the password flow (``begin_authorization``) and the SSO flow
        (``begin_authorization_from_session``) so both produce identical code
        records and PKCE binding.
        """
        self._prune(state)
        code = _random_token("code")
        state["authorizationCodes"][code] = {
            "code": code,
            "clientId": client_id,
            "redirectUri": redirect_uri,
            "scope": scope,
            "codeChallenge": code_challenge,
            "codeChallengeMethod": code_challenge_method or "S256",
            "session": self._seal_session(session),
            "expiresAt": _now_ms() + self._config.oauth.auth_code_ttl_seconds * 1000,
        }
        return code

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
        integration = _integration_for_client_id(self._config, client_id)
        session = self._resourcespace_service.authenticate(
            tenant_base_url=tenant_base_url,
            username=username,
            password=password,
            integration=integration,
        )
        session = _stamp_broker_session_metadata(
            session,
            client_id=client_id,
            integration=integration,
        )

        def _updater(state: dict[str, dict[str, Any]]) -> str:
            return self._mint_authorization_code(
                state,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                session=session,
            )

        return self._store.update(_updater)

    def begin_authorization_from_session(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
        session: dict[str, Any],
    ) -> str:
        """Mint an authorization code for an already-built session (SSO flow),
        rather than authenticating from credentials."""
        integration = _integration_for_client_id(self._config, client_id)
        session = _stamp_broker_session_metadata(
            session,
            client_id=client_id,
            integration=integration,
        )

        def _updater(state: dict[str, dict[str, Any]]) -> str:
            return self._mint_authorization_code(
                state,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                session=session,
            )

        return self._store.update(_updater)

    def begin_sso_authorization(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
        canva_state: str,
        tenant: dict[str, Any],
        correlation_id: str,
        initiator_key: str,
    ) -> str:
        """Create a single-use pending SSO handoff state and return its opaque
        broker-generated handoff token (the value round-tripped through
        ResourceSpace as ``state``)."""
        now = _now_ms()
        expires_at = now + self._config.resource_space.sso_pending_ttl_seconds * 1000
        purge_at = expires_at + self._config.resource_space.sso_replay_retention_seconds * 1000

        def _updater(state: dict[str, dict[str, Any]]) -> str:
            self._prune(state)
            per_source_limit = _max_pending_sso_states_per_source(self._config)
            now = _now_ms()
            outstanding_for_source = sum(
                1
                for record in state["pendingSsoStates"].values()
                if record.get("initiatorKey") == initiator_key
                and _is_active_pending_sso_state(record, now)
            )
            if outstanding_for_source >= per_source_limit:
                raise ResourceSpaceError(
                    "SSO_CAPACITY",
                    "Too many pending SSO sign-ins from this source; please retry shortly.",
                    503,
                )
            active_pending = sum(
                1
                for record in state["pendingSsoStates"].values()
                if _is_active_pending_sso_state(record, now)
            )
            if active_pending >= _MAX_PENDING_SSO_STATES:
                raise ResourceSpaceError(
                    "SSO_CAPACITY",
                    "Too many pending SSO sign-ins; please retry shortly.",
                    503,
                )
            handoff_state = _random_token("ssostate")
            state["pendingSsoStates"][handoff_state] = {
                "handoffState": handoff_state,
                "canvaState": canva_state,
                "clientId": client_id,
                "redirectUri": redirect_uri,
                "scope": scope,
                "codeChallenge": code_challenge,
                "codeChallengeMethod": code_challenge_method or "S256",
                "tenant": tenant,
                "correlationId": correlation_id,
                "initiatorKey": initiator_key,
                "createdAt": now,
                "expiresAt": expires_at,
                "usedAt": None,
                "purgeAt": purge_at,
            }
            return handoff_state

        return self._store.update(_updater)

    def _classify_pending_sso_record(
        self, record: dict[str, Any] | None
    ) -> dict[str, Any]:
        """Classify a pending SSO record without mutating store state."""
        if not record:
            return {"status": "invalid"}
        if record.get("usedAt"):
            return {"status": "replayed", "record": record}
        if _now_ms() > record["expiresAt"]:
            return {"status": "expired", "record": record}
        return {"status": "active", "record": record}

    def inspect_pending_sso_state(self, handoff_state: str) -> dict[str, Any]:
        """Non-mutating lookup of a pending SSO handoff state."""
        state = self._store.read()
        record = state.get("pendingSsoStates", {}).get(handoff_state)
        return self._classify_pending_sso_record(record)

    def complete_sso_authorization(
        self,
        handoff_state: str,
        *,
        session: dict[str, Any],
    ) -> dict[str, Any]:
        """Atomically consume an active handoff state and mint an authorization code.

        Re-checks that the state is still unused and unexpired inside the store
        transaction so validation failures before this call leave the state
        retryable and concurrent callbacks cannot mint multiple codes.
        """

        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
            self._prune(state)
            record = state["pendingSsoStates"].get(handoff_state)
            classified = self._classify_pending_sso_record(record)
            status = classified["status"]
            if status != "active":
                return classified

            record = classified["record"]
            client_id = record["clientId"]
            integration = _integration_for_client_id(self._config, client_id)
            session_with_metadata = _stamp_broker_session_metadata(
                session,
                client_id=client_id,
                integration=integration,
            )
            code = self._mint_authorization_code(
                state,
                client_id=client_id,
                redirect_uri=record["redirectUri"],
                scope=record["scope"],
                code_challenge=record["codeChallenge"],
                code_challenge_method=record["codeChallengeMethod"],
                session=session_with_metadata,
            )
            record["usedAt"] = _now_ms()
            return {"status": "valid", "code": code, "record": record}

        return self._store.update(_updater)

    def consume_pending_sso_state(self, handoff_state: str) -> dict[str, Any]:
        """Deprecated: prefer inspect + complete_sso_authorization.

        Kept for compatibility with tests that exercise state classification only.
        """

        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
            self._prune(state)
            record = state["pendingSsoStates"].get(handoff_state)
            if not record:
                return {"status": "invalid"}
            if record.get("usedAt"):
                return {"status": "replayed", "record": record}
            if _now_ms() > record["expiresAt"]:
                return {"status": "expired", "record": record}
            record["usedAt"] = _now_ms()
            return {"status": "valid", "record": record}

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
            return _write_token_pair_to_state(
                self,
                state,
                session=session,
                scope=scope,
                client_id=client_id,
                rotate_refresh_token=rotate_refresh_token,
                existing_refresh_token=existing_refresh_token,
            )

        return self._store.update(_updater)

    def exchange_authorization_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code: str,
        code_verifier: str | None,
    ) -> dict[str, Any]:
        if not _is_configured_client(self._config, client_id):
            return {"error": "invalid_client", "description": "Unknown OAuth client_id."}

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
            opened_session = self._try_open_session_dict(
                record["session"], bucket="authorizationCodes"
            )
            if opened_session is None:
                return {
                    "error": "invalid_grant",
                    "description": "Session no longer valid; please sign in again.",
                }
            return {"ok": True, "session": opened_session, "scope": record["scope"]}

        result = self._store.update(_updater)
        if result.get("error"):
            return result
        return self._create_token_pair(
            session=result["session"],
            scope=result["scope"],
            client_id=client_id,
        )

    def refresh_access_token(self, *, client_id: str, refresh_token: str) -> dict[str, Any]:
        # Rotate the refresh token on first use. Replays within
        # OAUTH_REFRESH_GRACE_SECONDS return the same token response (idempotent)
        # without minting another pair.
        if not _is_configured_client(self._config, client_id):
            return {"error": "invalid_client", "description": "Unknown OAuth client_id."}
        grace_ms = self._config.oauth.refresh_grace_seconds * 1000

        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any]:
            _prune_expired(state, refresh_grace_ms=grace_ms)
            record = state["refreshTokens"].get(refresh_token)
            if not record or record["clientId"] != client_id:
                return {"error": "invalid_grant", "description": "Refresh token not found."}
            if not _stamp_token_record_metadata(self._config, record):
                return {"error": "invalid_client", "description": "Unknown OAuth client_id."}
            opened_session = self._try_open_session_dict(record["session"], bucket="refreshTokens")
            if opened_session is None:
                return {
                    "error": "invalid_grant",
                    "description": "Session no longer valid; please sign in again.",
                }

            revoked_at = record.get("revokedAt")
            if revoked_at:
                if _now_ms() - revoked_at <= grace_ms:
                    cached = record.get("rotationResponse")
                    if isinstance(cached, dict) and cached.get("refresh_token"):
                        return {"ok": True, "tokens": cached}
                return {"error": "invalid_grant", "description": "Refresh token not found."}

            record["revokedAt"] = _now_ms()
            tokens = _write_token_pair_to_state(
                self,
                state,
                session=opened_session,
                scope=record["scope"],
                client_id=client_id,
            )
            record["rotationResponse"] = tokens
            return {"ok": True, "tokens": tokens}

        result = self._store.update(_updater)
        if result.get("error"):
            return result
        return result["tokens"]

    def read_access_token(self, token: str) -> dict[str, Any] | None:
        def _updater(state: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
            self._prune(state)
            record = state["accessTokens"].get(token)
            if record:
                if not _stamp_token_record_metadata(self._config, record):
                    return None
            return record

        record = self._store.update(_updater)
        if not record:
            return None
        return self._open_session(record)

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
        userinfo: dict[str, Any] = {
            "sub": summary["user"]["id"],
            "preferred_username": summary["user"]["username"],
            "name": summary["user"]["displayName"],
            "tenant_id": summary["tenant"]["id"],
            "tenant_slug": summary["tenant"]["slug"],
            "tenant_name": summary["tenant"]["name"],
            "role": summary["user"]["role"],
            "scope": record["scope"],
        }
        if summary["user"].get("email"):
            userinfo["email"] = summary["user"]["email"]
        return userinfo

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
    field_cipher: FieldCipher,
) -> AuthService:
    return AuthService(
        config=config,
        store=store,
        resourcespace_service=resourcespace_service,
        field_cipher=field_cipher,
    )
