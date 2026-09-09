"""Standby apply must not certify partial Kong reads."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def load_apply():
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(
            "apply_under_test", SCRIPTS / "apply_kong_standby.py"
        )
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        return loaded
    finally:
        sys.path.remove(str(SCRIPTS))


@pytest.mark.parametrize("response", [
    None,
    {},
    {"data": {}},
    {"data": ["not-an-object"]},
    {"data": [], "next": "/services?offset=hidden"},
])
def test_partial_or_invalid_collections_fail_closed(response):
    apply = load_apply()
    with pytest.raises(RuntimeError, match="invalid Kong|incomplete or invalid Kong"):
        apply.collection_rows(response, "services")


def test_upsert_requests_a_complete_bounded_name_page(monkeypatch):
    apply = load_apply()
    calls = []

    def request(method, path, payload=None):
        calls.append((method, path, payload))
        return {"data": []} if method == "GET" else {"id": "created"}

    monkeypatch.setattr(apply, "request", request)
    apply.upsert("services", "standby service", {"name": "standby service"})
    assert calls[0][0] == "GET"
    assert calls[0][1] == "/services?name=standby+service&size=1000"


def test_upsert_rejects_hidden_later_matches(monkeypatch):
    apply = load_apply()
    monkeypatch.setattr(
        apply,
        "request",
        lambda *args, **kwargs: {"data": [], "next": "/services?offset=hidden"},
    )
    with pytest.raises(RuntimeError, match="incomplete"):
        apply.upsert("services", "standby", {"name": "standby"})
