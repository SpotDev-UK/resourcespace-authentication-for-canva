"""Structured JSON logger compatible with the Node broker output format."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any


def _emit(level: str, message: str, context: dict[str, Any] | None = None) -> None:
    entry: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "level": level,
        "message": message,
    }
    if context:
        entry.update(context)
    line = json.dumps(entry)
    stream = sys.stderr if level == "error" else sys.stdout
    print(line, file=stream, flush=True)


def info(message: str, context: dict[str, Any] | None = None) -> None:
    _emit("info", message, context)


def warn(message: str, context: dict[str, Any] | None = None) -> None:
    _emit("warn", message, context)


def error(message: str, context: dict[str, Any] | None = None) -> None:
    _emit("error", message, context)
