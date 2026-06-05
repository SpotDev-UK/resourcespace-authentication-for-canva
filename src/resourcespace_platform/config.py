"""Application configuration loaded from environment variables.

Two-stage discipline:

1. `create_config()` builds an immutable snapshot from env vars with safe
   defaults that allow local dev with zero setup.
2. `validate_config_for_environment()` runs at app startup and refuses to
   boot when `APP_ENV` is anything other than ``development``/``test`` and
   the deployer has not provided the security-critical config that the
   broker cannot guess (Canva client secret, OAuth client id, redirect-uri
   allowlist, CORS origin, signed-asset secret).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping


DEFAULT_PORT = 3001

DEV_LIKE_ENVIRONMENTS = frozenset({"development", "test"})
DEFAULT_OAUTH_CLIENT_INTEGRATION = "canva"


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [entry.strip() for entry in value.split(",") if entry.strip()]


def _parse_tenant_json(value: str | None) -> list[dict[str, Any]]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _parse_oauth_clients_json(
    value: str | None,
) -> tuple[dict[str, "OAuthClientConfig"], str | None]:
    if not value:
        return {}, None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        return {}, f"OAUTH_CLIENTS_JSON must be valid JSON ({exc.msg})."
    if not isinstance(parsed, list):
        return {}, "OAUTH_CLIENTS_JSON must be a JSON array."

    clients: dict[str, OAuthClientConfig] = {}
    for index, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            return {}, f"OAUTH_CLIENTS_JSON entry {index} must be an object."

        client_id = str(entry.get("clientId") or entry.get("client_id") or "").strip()
        if not client_id:
            return {}, f"OAUTH_CLIENTS_JSON entry {index} must include clientId."

        raw_integration = entry.get("integration")
        integration = (
            str(raw_integration).strip()
            if raw_integration is not None and str(raw_integration).strip()
            else None
        )

        raw_allowlist = entry.get("redirectUriAllowlist")
        if raw_allowlist is None:
            raw_allowlist = entry.get("redirect_uri_allowlist")
        if isinstance(raw_allowlist, str):
            redirect_uri_allowlist = _split_csv(raw_allowlist)
        elif isinstance(raw_allowlist, list):
            redirect_uri_allowlist = [
                str(item).strip() for item in raw_allowlist if str(item).strip()
            ]
        elif raw_allowlist is None:
            redirect_uri_allowlist = []
        else:
            return (
                {},
                f"OAUTH_CLIENTS_JSON entry {index} redirectUriAllowlist must be a string or array.",
            )

        clients[client_id] = OAuthClientConfig(
            client_id=client_id,
            integration=integration,
            redirect_uri_allowlist=redirect_uri_allowlist,
        )

    return clients, None


def _parse_bool(value: str | None) -> bool:
    if not value:
        return False
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class OAuthClientConfig:
    client_id: str
    integration: str | None
    redirect_uri_allowlist: list[str]


@dataclass(frozen=True)
class OAuthConfig:
    issuer: str
    client_id: str
    allow_default_client_id: bool
    redirect_uri_allowlist: list[str]
    clients: dict[str, OAuthClientConfig]
    clients_parse_error: str | None
    token_ttl_seconds: int
    signed_url_ttl_seconds: int
    auth_code_ttl_seconds: int
    refresh_grace_seconds: int


@dataclass(frozen=True)
class SigningConfig:
    asset_secret: str
    canva_client_secret: str
    request_verification_mode: str
    request_timestamp_tolerance_seconds: int


@dataclass(frozen=True)
class RateLimitConfig:
    max_requests: int
    window_ms: int


@dataclass(frozen=True)
class ResourceSpaceConfig:
    mode: str
    allowed_hosts: list[str]
    tenants: list[dict[str, Any]]
    container_source: str


@dataclass(frozen=True)
class UploadConfig:
    """Limits for fetching Canva-supplied export URLs server-side.

    ``allowed_hosts`` is an exact-match host allowlist for the export URL.
    When empty, any public host is permitted (private IP ranges are still
    blocked unconditionally, see ``services/resourcespace/_upload.py``).
    """

    allowed_hosts: list[str]
    max_bytes: int
    max_image_pixels: int


@dataclass(frozen=True)
class MetricsConfig:
    bearer_token: str  # empty = endpoint returns aggregate-only counts to all callers


@dataclass(frozen=True)
class AppConfig:
    environment: str
    port: int
    base_url: str
    cors_origin: str
    storage_path: str
    oauth: OAuthConfig
    signing: SigningConfig
    rate_limit: RateLimitConfig
    resource_space: ResourceSpaceConfig
    upload: UploadConfig
    metrics: MetricsConfig


def _default_storage_path() -> str:
    return str(
        (Path(__file__).resolve().parent.parent.parent / ".data" / "platform-store.json")
    )


def create_config(env: Mapping[str, str] | None = None) -> AppConfig:
    """Build an immutable config snapshot from env vars."""
    source = env if env is not None else os.environ
    port = int(source.get("PORT", DEFAULT_PORT))
    base_url = source.get("BASE_URL", f"http://localhost:{port}")
    oauth_client_id = source.get("OAUTH_CLIENT_ID", "canva-dev-app")
    oauth_redirect_uri_allowlist = _split_csv(source.get("OAUTH_REDIRECT_URI_ALLOWLIST"))
    extra_oauth_clients, oauth_clients_parse_error = _parse_oauth_clients_json(
        source.get("OAUTH_CLIENTS_JSON")
    )
    oauth_clients = (
        {
            oauth_client_id: OAuthClientConfig(
                client_id=oauth_client_id,
                integration=DEFAULT_OAUTH_CLIENT_INTEGRATION,
                redirect_uri_allowlist=oauth_redirect_uri_allowlist,
            )
        }
        if oauth_client_id
        else {}
    )
    oauth_clients.update(extra_oauth_clients)

    return AppConfig(
        environment=source.get("APP_ENV", source.get("NODE_ENV", "development")),
        port=port,
        base_url=base_url,
        cors_origin=source.get("CORS_ORIGIN", "*"),
        storage_path=source.get("STORAGE_PATH", _default_storage_path()),
        oauth=OAuthConfig(
            issuer=source.get("OAUTH_ISSUER", base_url),
            client_id=oauth_client_id,
            allow_default_client_id=_parse_bool(source.get("OAUTH_ALLOW_DEFAULT_CLIENT_ID")),
            redirect_uri_allowlist=oauth_redirect_uri_allowlist,
            clients=oauth_clients,
            clients_parse_error=oauth_clients_parse_error,
            token_ttl_seconds=int(source.get("TOKEN_TTL_SECONDS", 900)),
            signed_url_ttl_seconds=int(source.get("SIGNED_URL_TTL_SECONDS", 300)),
            auth_code_ttl_seconds=int(source.get("AUTH_CODE_TTL_SECONDS", 300)),
            refresh_grace_seconds=int(source.get("OAUTH_REFRESH_GRACE_SECONDS", 30)),
        ),
        signing=SigningConfig(
            asset_secret=source.get("ASSET_SIGNING_SECRET", "development-signing-secret"),
            canva_client_secret=source.get("CANVA_CLIENT_SECRET", ""),
            request_verification_mode=source.get("CANVA_REQUEST_VERIFICATION_MODE", "smart"),
            request_timestamp_tolerance_seconds=int(
                source.get("CANVA_REQUEST_TIMESTAMP_TOLERANCE_SECONDS", 300)
            ),
        ),
        rate_limit=RateLimitConfig(
            max_requests=int(source.get("RATE_LIMIT_MAX_REQUESTS", 120)),
            window_ms=int(source.get("RATE_LIMIT_WINDOW_MS", 60_000)),
        ),
        resource_space=ResourceSpaceConfig(
            mode=source.get("RESOURCE_SPACE_MODE", "fixture"),
            allowed_hosts=_split_csv(source.get("RESOURCE_SPACE_ALLOWED_HOSTS")),
            tenants=_parse_tenant_json(source.get("RESOURCE_SPACE_TENANTS_JSON")),
            container_source=source.get("RESOURCE_SPACE_CONTAINER_SOURCE", "user_collections"),
        ),
        upload=UploadConfig(
            allowed_hosts=_split_csv(source.get("CANVA_UPLOAD_ALLOWED_HOSTS")),
            max_bytes=int(source.get("CANVA_UPLOAD_MAX_BYTES", 50 * 1024 * 1024)),
            max_image_pixels=int(source.get("CANVA_UPLOAD_MAX_IMAGE_PIXELS", 50_000_000)),
        ),
        metrics=MetricsConfig(
            bearer_token=source.get("METRICS_TOKEN", ""),
        ),
    )


class ConfigValidationError(RuntimeError):
    """Raised at startup when the broker is misconfigured for its environment."""


def validate_config_for_environment(config: AppConfig) -> None:
    """Refuse to boot if production-required settings are missing or unsafe.

    ``development`` and ``test`` environments are exempt — they keep the
    permissive defaults that make local work frictionless. Any other value
    of ``APP_ENV`` is treated as production-grade and held to the same
    security bar.
    """
    if config.environment in DEV_LIKE_ENVIRONMENTS:
        return

    problems: list[str] = []

    if config.oauth.clients_parse_error:
        problems.append(config.oauth.clients_parse_error)
    if config.signing.request_verification_mode != "required":
        problems.append(
            "CANVA_REQUEST_VERIFICATION_MODE must be 'required' outside development "
            "(currently '%s')." % config.signing.request_verification_mode
        )
    if not config.signing.canva_client_secret:
        problems.append("CANVA_CLIENT_SECRET must be set so the broker can verify Canva signatures.")
    if config.signing.asset_secret in ("", "development-signing-secret"):
        problems.append(
            "ASSET_SIGNING_SECRET must be set to a long random value (the default is unsafe)."
        )
    if not config.oauth.client_id:
        problems.append("OAUTH_CLIENT_ID must be set.")
    elif config.oauth.client_id == "canva-dev-app" and not config.oauth.allow_default_client_id:
        problems.append(
            "OAUTH_CLIENT_ID is the placeholder 'canva-dev-app'. Set it to a non-default "
            "client id, or set OAUTH_ALLOW_DEFAULT_CLIENT_ID=true to opt in to the placeholder "
            "(only safe when OAUTH_REDIRECT_URI_ALLOWLIST is tightly scoped — otherwise an "
            "attacker who guesses the client id can drive an OAuth flow against this broker)."
        )
    if not config.oauth.redirect_uri_allowlist:
        problems.append(
            "OAUTH_REDIRECT_URI_ALLOWLIST must list every redirect_uri Canva uses for this "
            "broker (comma-separated, exact match)."
        )
    for client_id, client in config.oauth.clients.items():
        if not client.redirect_uri_allowlist:
            problems.append(
                "OAuth client '%s' must define a redirect URI allowlist. Use "
                "OAUTH_REDIRECT_URI_ALLOWLIST for the primary Canva client or "
                "redirectUriAllowlist in OAUTH_CLIENTS_JSON for additional clients."
                % client_id
            )
    cors_origins = [o.strip() for o in config.cors_origin.split(",") if o.strip()]
    if not cors_origins or "*" in cors_origins:
        problems.append(
            "CORS_ORIGIN must be set to one or more specific origins, not '*' "
            "(comma-separated, e.g. "
            "https://app-<lowercased-app-id>.canva-apps.com,https://www.canva.com)."
        )

    if problems:
        joined = "\n  - ".join(problems)
        raise ConfigValidationError(
            "Refusing to start in environment '%s'. Fix the following before deploying:\n  - %s"
            % (config.environment, joined)
        )
