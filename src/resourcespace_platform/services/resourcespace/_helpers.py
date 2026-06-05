"""Pure-stdlib helpers shared by the fixture and live ResourceSpace backends."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode, urlparse


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


def _host_matches_pattern(host: str, pattern: str) -> bool:
    normalized = pattern.strip().lower()
    if not normalized:
        return False
    if normalized.startswith("."):
        return host.endswith(normalized)
    return host == normalized or host.endswith(f".{normalized}")


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
