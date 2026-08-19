"""Application configuration loaded from environment variables.

Two-stage discipline:

1. `create_config()` builds an immutable snapshot from env vars. When
   ``APP_ENV``/``NODE_ENV`` are unset, the environment defaults to
   ``production`` (fail closed).
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

DEFAULT_APP_ENV = "production"

DEV_LIKE_ENVIRONMENTS = frozenset({"development", "test"})
CLIENT_IP_LOG_DIAGNOSTICS_ENVIRONMENTS = frozenset({"development", "test", "staging", "uat"})
DEFAULT_OAUTH_CLIENT_INTEGRATION = "canva"
# RFC1918 + loopback + CGNAT defaults for container-platform edge proxies
# (Railway internal networking commonly uses 100.64.0.0/10).
DEFAULT_TRUSTED_PROXY_HOSTS = (
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10"
)


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [entry.strip() for entry in value.split(",") if entry.strip()]


def _parse_tenant_json(value: str | None) -> tuple[list[dict[str, Any]], str | None]:
    if not value:
        return [], None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        return [], f"RESOURCE_SPACE_TENANTS_JSON must be valid JSON ({exc.msg})."
    if not isinstance(parsed, list):
        return [], "RESOURCE_SPACE_TENANTS_JSON must be a JSON array."
    tenants: list[dict[str, Any]] = []
    for index, entry in enumerate(parsed):
        if not isinstance(entry, dict):
            return [], f"RESOURCE_SPACE_TENANTS_JSON entry {index} must be an object."
        tenant_id = str(entry.get("id") or "").strip()
        base_url = str(entry.get("baseUrl") or entry.get("base_url") or "").strip()
        if not tenant_id or not base_url:
            return (
                [],
                f"RESOURCE_SPACE_TENANTS_JSON entry {index} must include id and baseUrl.",
            )
        tenants.append(entry)
    return tenants, None


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
    refresh_token_ttl_seconds: int


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
    tenants_parse_error: str | None
    container_source: str
    asset_allowed_hosts: list[str]
    asset_proxy_max_bytes: int
    sso_enabled: bool
    sso_system_key: str
    sso_pending_ttl_seconds: int
    sso_replay_retention_seconds: int


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
    storage_encryption_key: str
    store_prune_interval_seconds: int
    client_ip_header: str
    trusted_proxy_hosts: list[str]
    client_ip_log_key: str
    client_ip_log_diagnostics: bool
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
    if env is not None:
        source: Mapping[str, str] = dict(env)
        if (
            "APP_ENV" not in source
            and "NODE_ENV" not in source
            and os.environ.get("PYTEST_CURRENT_TEST")
        ):
            source = {**{"APP_ENV": "development"}, **dict(env)}
    else:
        source = os.environ
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
    environment = (
        source.get("APP_ENV") or source.get("NODE_ENV") or DEFAULT_APP_ENV
    ).strip()
    tenants, tenants_parse_error = _parse_tenant_json(source.get("RESOURCE_SPACE_TENANTS_JSON"))
    default_client_ip_header = "" if environment in DEV_LIKE_ENVIRONMENTS else "x-real-ip"
    default_trusted_proxy_hosts = (
        _split_csv(DEFAULT_TRUSTED_PROXY_HOSTS)
        if environment not in DEV_LIKE_ENVIRONMENTS
        else []
    )
    client_ip_header = source.get("CLIENT_IP_HEADER", default_client_ip_header).strip().lower()
    trusted_proxy_raw = source.get("TRUSTED_PROXY_HOSTS")
    trusted_proxy_hosts = (
        _split_csv(trusted_proxy_raw)
        if trusted_proxy_raw is not None
        else default_trusted_proxy_hosts
    )
    client_ip_log_key = source.get("CLIENT_IP_LOG_KEY", "").strip()
    client_ip_log_diagnostics = _parse_bool(source.get("CLIENT_IP_LOG_DIAGNOSTICS"))

    return AppConfig(
        environment=environment,
        port=port,
        base_url=base_url,
        cors_origin=source.get("CORS_ORIGIN", "*"),
        storage_path=source.get("STORAGE_PATH", _default_storage_path()),
        storage_encryption_key=source.get("STORAGE_ENCRYPTION_KEY", ""),
        store_prune_interval_seconds=int(source.get("STORE_PRUNE_INTERVAL_SECONDS", 3600)),
        client_ip_header=client_ip_header,
        trusted_proxy_hosts=trusted_proxy_hosts,
        client_ip_log_key=client_ip_log_key,
        client_ip_log_diagnostics=client_ip_log_diagnostics,
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
            refresh_token_ttl_seconds=int(
                source.get("REFRESH_TOKEN_TTL_SECONDS", 30 * 24 * 60 * 60)
            ),
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
            # Normalise so case/whitespace variants ("Live", "live ") cannot
            # slip past the mode-keyed SSRF guard and startup validation while
            # still dispatching to the live backend.
            mode=source.get("RESOURCE_SPACE_MODE", "fixture").strip().lower(),
            allowed_hosts=_split_csv(source.get("RESOURCE_SPACE_ALLOWED_HOSTS")),
            tenants=tenants,
            tenants_parse_error=tenants_parse_error,
            container_source=source.get("RESOURCE_SPACE_CONTAINER_SOURCE", "user_collections"),
            asset_allowed_hosts=_split_csv(source.get("RESOURCE_SPACE_ASSET_ALLOWED_HOSTS")),
            asset_proxy_max_bytes=int(
                source.get("RESOURCE_SPACE_ASSET_PROXY_MAX_BYTES", 50 * 1024 * 1024)
            ),
            sso_enabled=_parse_bool(source.get("RESOURCE_SPACE_SSO_ENABLED")),
            sso_system_key=source.get("RESOURCE_SPACE_SSO_SYSTEM_KEY", "canva"),
            sso_pending_ttl_seconds=int(
                source.get("RESOURCE_SPACE_SSO_PENDING_TTL_SECONDS", 600)
            ),
            sso_replay_retention_seconds=int(
                source.get("RESOURCE_SPACE_SSO_REPLAY_RETENTION_SECONDS", 600)
            ),
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
    if os.environ.get("RAILWAY_ENVIRONMENT") and config.environment in DEV_LIKE_ENVIRONMENTS:
        raise ConfigValidationError(
            "Refusing to start on Railway with APP_ENV='%s'. Set APP_ENV to "
            "production, staging, or uat and provide the required security "
            "configuration. Discovery runs belong on localhost, not a deployed "
            "Railway service." % config.environment
        )

    if config.environment in DEV_LIKE_ENVIRONMENTS:
        return

    problems: list[str] = []

    if config.oauth.clients_parse_error:
        problems.append(config.oauth.clients_parse_error)
    if config.resource_space.tenants_parse_error:
        problems.append(config.resource_space.tenants_parse_error)
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
    if config.resource_space.mode not in ("fixture", "live"):
        problems.append(
            "RESOURCE_SPACE_MODE must be 'fixture' or 'live' (got '%s'). Any other value is "
            "treated as live at runtime, which is easy to misconfigure." % config.resource_space.mode
        )
    if not config.storage_encryption_key:
        problems.append(
            "STORAGE_ENCRYPTION_KEY must be set outside development/test. Generate one with "
            "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"`."
        )
    else:
        try:
            from cryptography.fernet import Fernet

            Fernet(config.storage_encryption_key.encode("ascii"))
        except (ValueError, TypeError):
            problems.append(
                "STORAGE_ENCRYPTION_KEY must be a url-safe base64-encoded 32-byte Fernet key. "
                "Generate one with "
                "`python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"`."
            )

    if config.client_ip_header and not config.trusted_proxy_hosts:
        problems.append(
            "TRUSTED_PROXY_HOSTS must list the CIDRs or addresses of reverse proxies "
            "that may set CLIENT_IP_HEADER (%s). The header is ignored for direct "
            "connections to prevent client IP spoofing." % config.client_ip_header
        )

    if (
        config.client_ip_log_diagnostics
        and config.environment.lower() not in CLIENT_IP_LOG_DIAGNOSTICS_ENVIRONMENTS
    ):
        problems.append(
            "CLIENT_IP_LOG_DIAGNOSTICS is permitted only when APP_ENV is one of "
            "development, test, staging, or uat (currently '%s'). It logs raw "
            "transportPeer addresses; disable before production deploy."
            % config.environment
        )

    if problems:
        joined = "\n  - ".join(problems)
        raise ConfigValidationError(
            "Refusing to start in environment '%s'. Fix the following before deploying:\n  - %s"
            % (config.environment, joined)
        )
