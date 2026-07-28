"""Tests for strict store loads on ordinary writes."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from resourcespace_platform.services.json_store import JsonStoreLoadError, create_json_store


def test_update_refuses_to_overwrite_corrupt_store() -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    Path(storage_path).write_text("{not-json")
    store = create_json_store(storage_path)

    with pytest.raises(JsonStoreLoadError):
        store.update(lambda state: state)

    assert Path(storage_path).read_text() == "{not-json"

    if os.path.exists(storage_path):
        os.remove(storage_path)


def test_update_refuses_null_bucket_overwrite() -> None:
    storage_path = tempfile.mkstemp(suffix=".json")[1]
    os.remove(storage_path)
    Path(storage_path).write_text(json.dumps({"accessTokens": None}))
    store = create_json_store(storage_path)

    with pytest.raises(JsonStoreLoadError):
        store.update(lambda state: state)

    assert json.loads(Path(storage_path).read_text()) == {"accessTokens": None}

    if os.path.exists(storage_path):
        os.remove(storage_path)
