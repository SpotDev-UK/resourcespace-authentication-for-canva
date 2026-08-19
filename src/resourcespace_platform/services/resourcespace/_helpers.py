"""Helpers shared by the fixture and live ResourceSpace backends.

Mostly pure stdlib; ``pin_request`` uses ``httpx.URL`` so its host
canonicalisation matches exactly what the httpx client would connect to.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx


SUPPORTED_IMAGE_MIME_TYPES: frozenset[str] = frozenset(
    {"image/jpeg", "image/png", "image/svg+xml", "image/webp", "image/heic"}
)

RESOURCE_SPACE_CANVA_USER_AGENT = "python-httpx RSCanva"
RESOURCE_SPACE_CANVA_INTEGRATION = "canva"


class ResourceSpaceError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def _slugify(value: str) -> str:
    return re.sub(r"(^-+|-+$)", "", re.sub(r"[^a-z0-9]+", "-", value.lower()))


def normalize_base_url(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if not candidate.startswith("http://") and not candidate.startswith("https://"):
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _normalize_api_url(base_url: str, override: str | None) -> str:
    if override:
        return override if override.endswith("/") else f"{override}/"
    return f"{base_url}/api/"


def _canonical_pattern(pattern: str) -> str:
    """UTS46-canonicalise an allowlist pattern to ASCII, preserving a leading
    dot. A configured Unicode pattern (e.g. ``faß.de`` or ``.faß.de``) must be
    canonicalised the same way as the host it is matched against, otherwise a
    canonical host (``xn--fa-hia.de``) would never match a raw pattern."""
    p = pattern.strip().lower()
    if not p:
        return ""
    try:
        if p.startswith("."):
            return "." + canonical_ascii_host(p[1:])
        return canonical_ascii_host(p)
    except ResourceSpaceError:
        return p


def _host_matches_pattern(host: str, pattern: str) -> bool:
    try:
        chost = canonical_ascii_host(host)
    except ResourceSpaceError:
        return False
    normalized = _canonical_pattern(pattern)
    if not normalized:
        return False
    if normalized.startswith("."):
        return chost.endswith(normalized)
    return chost == normalized or chost.endswith(f".{normalized}")


def _host_matches_strict(host: str, pattern: str) -> bool:
    """Strict allowlist match. A bare entry (``cdn.example.com``) matches only
    that exact host; it does NOT authorise subdomains. A leading-dot entry
    (``.example.com``) matches that domain and its subdomains. Both host and
    pattern are UTS46-canonicalised first. Used by the asset proxy allowlist,
    which is documented as exact-by-default."""
    try:
        chost = canonical_ascii_host(host)
    except ResourceSpaceError:
        return False
    normalized = _canonical_pattern(pattern)
    if not normalized:
        return False
    if normalized.startswith("."):
        return chost == normalized[1:] or chost.endswith(normalized)
    return chost == normalized


def _ip_is_blocked(ip: "ipaddress._BaseAddress") -> bool:
    """Return True for any address the broker must not connect to."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        # IPv6 site-local (fec0::/10) reports is_global=True under Python 3.11,
        # so it must be rejected explicitly (is_site_local is IPv6-only).
        or getattr(ip, "is_site_local", False)
        # Catches CGNAT/shared address space (100.64.0.0/10) and anything else
        # that is not a globally routable address. Python's is_private does not
        # cover 100.64.0.0/10, so this is the backstop.
        or not ip.is_global
    )


def canonical_ascii_host(host: str) -> str:
    """UTS46-canonical ASCII form of a bare hostname, matching httpx's
    connect-time canonicalisation.

    IP literals and ASCII hosts are returned lowercased; Unicode domains are
    IDNA/UTS46-encoded. This must be applied BEFORE resolving or allowlist-
    matching a host so validation uses the exact host httpx would connect to,
    never the stdlib IDNA-2003 sibling (e.g. ``faß.de`` must become
    ``xn--fa-hia.de``, not ``fass.de``, which is a different domain). Empty host
    returns ''.
    """
    if not host:
        return ""
    if host.isascii():
        return host.lower()
    try:
        return httpx.URL(scheme="https", host=host).raw_host.decode("ascii")
    except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
        raise ResourceSpaceError("FORBIDDEN", "Invalid host name.", 400) from exc


def _is_private_ip(host: str) -> bool:
    """Return True if `host` resolves to any non-public / internal address.

    Shared by the tenant-resolution path (``service.get_configured_tenant``),
    the signed-asset proxy fetch (``asset_service``) and the upload export
    fetch (``_upload._validate_export_url``) so all three enforce the same
    fail-closed rule. The host is canonicalised (UTS46) first so the address
    that is validated is the one httpx would connect to.
    """
    try:
        host = canonical_ascii_host(host)
    except ResourceSpaceError:
        return True  # invalid IDN -> treat as unsafe
    if not host:
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        # Doesn't resolve, or an invalid DNS label (e.g. >63-byte label, which
        # getaddrinfo raises UnicodeError for): treat as unsafe rather than risk
        # a TOCTOU where it resolves to an internal address mid-request.
        return True
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            return True
    return False


def resolve_pinned_addresses(host: str) -> list[str]:
    """Resolve `host`, require EVERY resolved address to be public, and return
    ALL validated addresses ordered IPv4-first.

    Raises ``ResourceSpaceError`` if the host does not resolve or any address is
    non-public. Returning every address (not just the first) lets the caller
    fall back at the connection layer: some deployments (e.g. Railway) disable
    outbound IPv6, so an IPv6-first resolution must still be able to reach the
    working IPv4 address rather than failing with ENETUNREACH. Pinning to these
    validated addresses closes the DNS-rebinding TOCTOU: the resolution that is
    validated is the same one connected to (httpx is handed IP literals so it
    does not re-resolve at connect time).
    """
    host = canonical_ascii_host(host)
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError) as exc:
        # gaierror: does not resolve. UnicodeError: invalid DNS label (e.g. a
        # label longer than 63 bytes). Both are a controlled rejection, not 500.
        raise ResourceSpaceError(
            "FORBIDDEN",
            "This ResourceSpace URL could not be resolved.",
            403,
        ) from exc
    v4: list[str] = []
    v6: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise ResourceSpaceError(
                "FORBIDDEN", "Host resolves to a non-public address.", 403
            )
        (v6 if ip.version == 6 else v4).append(addr)
    ordered: list[str] = []
    for addr in v4 + v6:  # IPv4 first (Railway disables outbound IPv6 by default)
        if addr not in ordered:
            ordered.append(addr)
    if not ordered:
        raise ResourceSpaceError("FORBIDDEN", "Host has no usable address.", 403)
    return ordered


def resolve_pinned_ip(host: str) -> str:
    """First validated address for `host` (IPv4-first). See
    ``resolve_pinned_addresses`` for the connection-fallback rationale."""
    return resolve_pinned_addresses(host)[0]


def _authority_for_header(ascii_host: str, port: int | None) -> str:
    """Serialise an already-canonical ASCII host for the ``Host`` header,
    bracketing IPv6 literals and appending an explicit port if present."""
    try:
        ip = ipaddress.ip_address(ascii_host)
        authority = f"[{ascii_host}]" if ip.version == 6 else ascii_host
    except ValueError:
        authority = ascii_host
    return authority if port is None else f"{authority}:{port}"


def pin_request(
    url: str, *, allowed_hosts: list[str] | None = None
) -> tuple[list[str], dict[str, str], dict[str, Any]]:
    """Build SSRF-safe request arguments for an outbound https fetch.

    Returns ``(pinned_urls, extra_headers, extensions)``. ``pinned_urls`` is one
    URL per validated resolved address (IPv4-first), each with the host replaced
    by that IP so httpx connects to that exact address without re-resolving; the
    caller tries them in order for connection-level fallback. The original host
    is preserved for the TLS SNI/certificate check (``sni_hostname``) and a
    canonical ASCII ``Host`` header.

    Canonicalisation, allowlist matching and address validation all happen on
    the ``httpx.URL.raw_host`` (UTS46 IDNA) form, so the host that is checked and
    resolved is exactly the one httpx would connect to. The stdlib
    ``str.encode("idna")`` must NOT be used: it applies IDNA 2003 and maps e.g.
    ``faß.de`` to ``fass.de`` (a different domain resolving to different IPs),
    which could target the wrong host. When ``allowed_hosts`` is given, the
    canonical host must match it (strict: bare = exact, leading dot = subdomain)
    before any DNS resolution. Raises ``ResourceSpaceError`` for a non-https URL,
    a missing host, a non-allowlisted host, or a host that resolves to a
    non-public address.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError) as exc:
        raise ResourceSpaceError("FORBIDDEN", "Invalid URL.", 400) from exc
    if parsed.scheme != "https" or not parsed.host:
        raise ResourceSpaceError(
            "FORBIDDEN", "Only https URLs with a hostname may be fetched.", 400
        )
    # Canonical ASCII host (UTS46 punycode for IDN, or the IP literal for IPs).
    ascii_host = parsed.raw_host.decode("ascii")
    if allowed_hosts and not any(
        _host_matches_strict(ascii_host, pattern) for pattern in allowed_hosts
    ):
        raise ResourceSpaceError(
            "FORBIDDEN", "Host is not in the configured allowlist.", 403
        )
    addresses = resolve_pinned_addresses(ascii_host)
    host_header = _authority_for_header(ascii_host, parsed.port)
    pinned_urls = [str(parsed.copy_with(host=ip)) for ip in addresses]
    return pinned_urls, {"Host": host_header}, {"sni_hostname": ascii_host}


def _encode_collection_container_id(ref: Any) -> str:
    return f"collection:{ref}"


def _decode_collection_container_id(container_id: str | None) -> str | None:
    if not container_id or not container_id.startswith("collection:"):
        return None
    return container_id[len("collection:") :]


def _decode_fixture_container_id(container_id: str | None) -> str | None:
    if not container_id or not container_id.startswith("fixture:"):
        return None
    return container_id[len("fixture:") :]


def _mime_type_from_extension(extension: str | None) -> str:
    normalized = (extension or "").strip().lower()
    return {
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "svg": "image/svg+xml",
        "webp": "image/webp",
        "heic": "image/heic",
        "tif": "image/tiff",
        "tiff": "image/tiff",
        "gif": "image/gif",
    }.get(normalized, "application/octet-stream")


def _pick_asset_name(record: dict[str, Any]) -> str:
    for candidate in (
        record.get("name"),
        record.get("title"),
        record.get("resource_title"),
        record.get("field8"),
        record.get("original_filename"),
        record.get("file_path"),
        f"Asset {record.get('ref') or record.get('id')}",
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return "Untitled asset"


def _pick_asset_description(record: dict[str, Any]) -> str:
    for candidate in (
        record.get("summary"),
        record.get("description"),
        record.get("field73"),
        record.get("field3"),
        record.get("country"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return ""


def _to_iso_date(value: Any) -> str | None:
    if not value:
        return None
    try:
        if isinstance(value, (int, float)):
            return (
                datetime.fromtimestamp(float(value), tz=timezone.utc)
                .isoformat()
                .replace("+00:00", "Z")
            )
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError):
        return None


def _sort_collections(collections: list[dict[str, Any]], _sort: str | None = None) -> list[dict[str, Any]]:
    return sorted(collections, key=lambda collection: str(collection.get("name", "")))


def _broker_integration_from_session(session: dict[str, Any]) -> str | None:
    broker = session.get("broker")
    if not isinstance(broker, dict):
        return None
    integration = broker.get("integration")
    return integration if isinstance(integration, str) else None


def _resourcespace_request_headers(integration: str | None = None) -> dict[str, str]:
    if integration == RESOURCE_SPACE_CANVA_INTEGRATION:
        return {"User-Agent": RESOURCE_SPACE_CANVA_USER_AGENT}
    return {}


def _build_signed_api_url(
    *, api_url: str, username: str, session_key: str, params: dict[str, Any]
) -> str:
    pairs: list[tuple[str, str]] = [("user", username), ("function", str(params["function"]))]
    for key, value in params.items():
        if key == "function" or value is None or value == "":
            continue
        pairs.append((key, str(value)))
    query_string = urlencode(pairs, doseq=False)
    signature = hashlib.sha256(f"{session_key}{query_string}".encode("utf-8")).hexdigest()
    return f"{api_url}?{query_string}&sign={signature}&authmode=sessionkey"
