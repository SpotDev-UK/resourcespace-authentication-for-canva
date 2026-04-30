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
}


def _clone_initial_state() -> dict[str, dict[str, Any]]:
    return copy.deepcopy(_INITIAL_STATE)


class JsonStore:
    def __init__(self, file_path: str) -> None:
        self._file_path = Path(file_path)
        self._lock = threading.Lock()
        self._ensure_file()

    def _ensure_file(self) -> None:
        self._file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self._file_path.exists():
            self._file_path.write_text(json.dumps(_clone_initial_state(), indent=2))
            self._restrict_perms(self._file_path)
        self._restrict_perms(self._file_path.parent)

    @staticmethod
    def _restrict_perms(path: Path) -> None:
        # Tokens, refresh tokens, and ResourceSpace session keys are stored
        # in cleartext in this file; lock it to the broker user.
        try:
            if path.is_dir():
                os.chmod(path, 0o700)
            else:
                os.chmod(path, 0o600)
        except OSError:
            # Some filesystems (e.g. mounted Docker volumes on macOS) don't
            # honour chmod; surfacing a startup failure here would block
            # local dev. Log and continue — production deploys are expected
            # to run on a real POSIX filesystem where chmod takes effect.
            pass

    def _load(self) -> dict[str, dict[str, Any]]:
        self._ensure_file()
        try:
            parsed = json.loads(self._file_path.read_text())
        except (OSError, json.JSONDecodeError):
            return _clone_initial_state()

        merged = _clone_initial_state()
        if isinstance(parsed, dict):
            for key in merged:
                if isinstance(parsed.get(key), dict):
                    merged[key] = parsed[key]
        return merged

    def _save(self, state: dict[str, Any]) -> None:
        self._ensure_file()
        tmp_path = self._file_path.with_suffix(self._file_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(state, indent=2, default=str))
        self._restrict_perms(tmp_path)
        os.replace(tmp_path, self._file_path)

    def read(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return self._load()

    def update(self, updater: Callable[[dict[str, dict[str, Any]]], Any]) -> Any:
        with self._lock:
            state = self._load()
            result = updater(state)
            self._save(state)
            return result


def create_json_store(file_path: str) -> JsonStore:
    return JsonStore(file_path)
