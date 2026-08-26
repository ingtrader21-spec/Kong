#!/usr/bin/env python3
"""Delete only objects tagged by the Kong standby release."""
from __future__ import annotations

import json
import urllib.parse
import urllib.request

ADMIN = "http://127.0.0.1:8001"
TAG = "codestra-kong-standby-20260820"


def call(method, path):
    req = urllib.request.Request(ADMIN + path, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return None if response.status == 204 else json.load(response)


def main():
    tagged = urllib.parse.quote(TAG, safe="")
    for collection in ("plugins", "routes", "services"):
        data = call("GET", f"/{collection}?tags={tagged}").get("data", [])
        for item in data:
            call("DELETE", f"/{collection}/{item['id']}")
    print("KONG_STANDBY_ROLLBACK=PASS")


if __name__ == "__main__":
    main()
