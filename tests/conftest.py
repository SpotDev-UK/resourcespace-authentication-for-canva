"""Shared pytest fixtures for the test suite."""
from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest

import resourcespace_platform.logger as logger_module

# Substrings that must not appear in logged context string values.
_FORBIDDEN_CONTEXT_SUBSTRINGS = (
    "fixture-sso",  # fixture SSO session keys
    "-password",  # fixture user passwords
    "@example.com",  # test email literals
    "rs-session-key",  # live-backend test session keys
)

_BROKER_TOKEN_PREFIXES = ("at_", "rt_", "code_", "ssostate_")


def _context_string_values(entry: dict[str, Any]) -> list[str]:
    context = entry.get("context")
    if not isinstance(context, dict):
        return []
    return [value for value in context.values() if isinstance(value, str)]


def _assert_no_secrets_in_log_context(entry: dict[str, Any]) -> None:
    for value in _context_string_values(entry):
        for marker in _FORBIDDEN_CONTEXT_SUBSTRINGS:
            assert marker not in value, (
                f"log entry for {entry.get('message')!r} context value contained "
                f"forbidden marker {marker!r}"
            )
        for prefix in _BROKER_TOKEN_PREFIXES:
            assert not value.startswith(prefix), (
                f"log entry for {entry.get('message')!r} context value looked like a "
                f"broker token ({prefix!r})"
            )


@pytest.fixture(autouse=True)
def captured_logs(monkeypatch: pytest.MonkeyPatch) -> Generator[list[dict[str, Any]], None, None]:
    records: list[dict[str, Any]] = []

    def _record(level: str, message: str, context: dict[str, Any] | None = None) -> None:
        entry: dict[str, Any] = {"level": level, "message": message}
        if context:
            entry["context"] = context
        records.append(entry)

    monkeypatch.setattr(logger_module, "_emit", _record)
    yield records

    for entry in records:
        _assert_no_secrets_in_log_context(entry)
