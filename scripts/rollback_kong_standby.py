#!/usr/bin/env python3
"""Delete only objects tagged by the Kong standby release."""
from __future__ import annotations

import sys
import urllib.parse
from pathlib import Path

SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_admin_channel import admin_request, confirm_unchanged, entity_id  # noqa: E402

TAG = "codestra-kong-standby-20260820"
PAGE_SIZE = 1000


def call(method, path):
    # Admin has no host publication; every call enters the verified gateway
    # container instead of crossing a management port.
    return admin_request(method, path)


def main():
    tagged = urllib.parse.quote(TAG, safe="")
    for collection in ("plugins", "routes", "services"):
        # Always drain the first page. Following an offset while deleting from
        # the same collection can skip rows as the result set contracts.
        deleted: set[str] = set()
        while True:
            response = call("GET", f"/{collection}?tags={tagged}&size={PAGE_SIZE}") or {}
            data = response.get("data")
            if not isinstance(data, list):
                raise RuntimeError(f"invalid Kong {collection} collection")
            if not data:
                break
            identifiers = [entity_id(item.get("id"), collection.rstrip("s"))
                           for item in data if isinstance(item, dict)]
            if len(identifiers) != len(data) or len(identifiers) != len(set(identifiers)):
                raise RuntimeError(f"invalid Kong {collection} identities")
            if deleted.intersection(identifiers):
                raise RuntimeError(f"Kong {collection} rollback made no progress")
            for identifier in identifiers:
                call("DELETE", f"/{collection}/{identifier}")
                deleted.add(identifier)
    confirm_unchanged()
    print("KONG_STANDBY_ROLLBACK=PASS")


if __name__ == "__main__":
    main()
