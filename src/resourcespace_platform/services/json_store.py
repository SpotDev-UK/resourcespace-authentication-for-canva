"""Simple JSON-file persistence.

Single-instance UAT-grade storage. For horizontal scale, swap in a
Postgres-backed implementation behind the same `read` / `update` interface.
"""
from __future__ import annotations

import copy
import json
import os
import threading
from pathlib import Path
from typing import Any, Callable


_INITIAL_STATE: dict[str, dict[str, Any]] = {
    "authorizationCodes": {},
    "accessTokens": {},
    "refreshTokens": {},
    "assetGrants": {},
    "pendingSsoStates": {},
}


def _clone_initial_state() -> dict[str, dict[str, Any]]:
    return copy.deepcopy(_INITIAL_STATE)


class JsonStoreLoadError(OSError):
    """Raised when the store file cannot be read or parsed."""


class JsonStore:
    def __init__(self, file_path: str, *, require_secure_permissions: bool = False) -> None:
        self._file_path = Path(file_path)
        self._require_secure_permissions = require_secure_permissions
        self._lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self) -> None:
        self._file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self._file_path.exists():
            self._file_path.write_text(json.dumps(_clone_initial_state(), indent=2))
        # Restrict (and, outside dev/test, verify) the store file's permissions
        # on EVERY startup, not only at creation. An existing store left
        # world-readable (mode 0644) by a prior deploy or manual edit must be
        # locked down, not silently trusted.
        self._restrict_perms(self._file_path, fatal=self._require_secure_permissions)
        # The parent directory lock is defence-in-depth: keep it best-effort so
        # a STORAGE_PATH placed in a shared, broker-unowned directory does not
        # block startup. The store file above carries the secrets and is the one
        # whose permissions must hold.
        self._restrict_perms(self._file_path.parent, fatal=False)

    def _restrict_perms(self, path: Path, *, fatal: bool) -> None:
        # Tokens, refresh tokens, and ResourceSpace session keys are stored
        # in cleartext in this file; lock it to the broker user.
        try:
            if path.is_dir():
                os.chmod(path, 0o700)
            else:
                os.chmod(path, 0o600)
        except OSError as exc:
            # Some filesystems (e.g. mounted Docker volumes on macOS) don't
            # honour chmod. In dev/test that is tolerated so local work is
            # frictionless. Outside dev/test a failed chmod on the store file
            # means the cleartext secrets may be world-readable, so treat it as
            # a fatal startup error rather than silently continuing.
            if fatal:
                raise RuntimeError(
                    f"Refusing to start: could not restrict permissions on {path} "
                    f"({exc}). The store holds cleartext session keys and tokens and "
                    "must be lockable to the broker user."
                ) from exc

    def _merge_store(self, parsed: Any, *, strict: bool) -> dict[str, dict[str, Any]]:
        if not isinstance(parsed, dict):
            if strict:
                raise JsonStoreLoadError("Store root must be a JSON object.")
            return _clone_initial_state()

        merged = _clone_initial_state()
        for key in merged:
            if key not in parsed:
                continue
            bucket = parsed[key]
            if bucket is None:
                if strict:
                    raise JsonStoreLoadError(f"Store bucket {key!r} must not be null.")
                continue
            if not isinstance(bucket, dict):
                if strict:
                    raise JsonStoreLoadError(f"Store bucket {key!r} must be a JSON object.")
                continue
            merged[key] = bucket
        return merged

    def _load(self, *, strict: bool = False) -> dict[str, dict[str, Any]]:
        self._ensure_file()
        try:
            parsed = json.loads(self._file_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            if strict:
                raise JsonStoreLoadError(
                    f"Could not load store at {self._file_path}: {exc}"
                ) from exc
            return _clone_initial_state()

        return self._merge_store(parsed, strict=strict)

    def _save(self, state: dict[str, Any]) -> None:
        self._ensure_file()
        tmp_path = self._file_path.with_suffix(self._file_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(state, indent=2, default=str))
        self._restrict_perms(tmp_path, fatal=self._require_secure_permissions)
        os.replace(tmp_path, self._file_path)

    def read(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return self._load()

    def update(self, updater: Callable[[dict[str, dict[str, Any]]], Any]) -> Any:
        with self._lock:
            state = self._load(strict=True)
            result = updater(state)
            self._save(state)
            return result

    def update_strict(self, updater: Callable[[dict[str, dict[str, Any]]], Any]) -> Any:
        """Alias for :meth:`update` (all writes require a valid store load)."""
        with self._lock:
            state = self._load(strict=True)
            result = updater(state)
            self._save(state)
            return result


def create_json_store(file_path: str, *, require_secure_permissions: bool = False) -> JsonStore:
    return JsonStore(file_path, require_secure_permissions=require_secure_permissions)
