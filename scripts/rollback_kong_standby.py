#!/usr/bin/env python3
"""Delete only objects tagged by the Kong standby release."""
from __future__ import annotations

import sys
import urllib.parse
from pathlib import Path

SCRIPTS = str(Path(__file__).resolve().parent)
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

from kong_admin_channel import admin_request, confirm_unchanged  # noqa: E402

TAG = "codestra-kong-standby-20260820"


def call(method, path):
    # Admin has no host publication; every call enters the verified gateway
    # container instead of crossing a management port.
    return admin_request(method, path)


def main():
    tagged = urllib.parse.quote(TAG, safe="")
    for collection in ("plugins", "routes", "services"):
        data = (call("GET", f"/{collection}?tags={tagged}") or {}).get("data", [])
        for item in data:
            call("DELETE", f"/{collection}/{item['id']}")
    confirm_unchanged()
    print("KONG_STANDBY_ROLLBACK=PASS")


if __name__ == "__main__":
    main()
