"""Rollback must delete every owned object without unsafe offset pagination."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_rollback():
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(
            "rollback_under_test", SCRIPTS / "rollback_kong_standby.py"
        )
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        return loaded
    finally:
        sys.path.remove(str(SCRIPTS))


def test_rollback_drains_each_collection_without_offset_skips(monkeypatch):
    rollback = load_rollback()
    remaining = {
        collection: [f"00000000-0000-0000-0000-{number:012d}" for number in range(1, 4)]
        for collection in ("plugins", "routes", "services")
    }
    calls = []

    def request(method, path):
        calls.append((method, path))
        collection = path.split("/", 2)[1].split("?", 1)[0]
        if method == "GET":
            return {"data": [{"id": value} for value in remaining[collection][:2]],
                    "next": "/ignored-offset" if len(remaining[collection]) > 2 else None}
        remaining[collection].remove(path.rsplit("/", 1)[1])
        return None

    monkeypatch.setattr(rollback, "call", request)
    monkeypatch.setattr(rollback, "confirm_unchanged", lambda: None)
    rollback.main()
    assert remaining == {"plugins": [], "routes": [], "services": []}
    assert not any("offset=" in path for _, path in calls)


def test_rollback_rejects_invalid_response_ids(monkeypatch):
    rollback = load_rollback()
    monkeypatch.setattr(rollback, "call", lambda method, path: {"data": [{"id": "../route"}]})
    with pytest.raises(RuntimeError, match="invalid Kong"):
        rollback.main()
