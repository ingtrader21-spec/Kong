#!/usr/bin/env python3
"""Fail-closed, secret-free verification of the deployed gateway topology."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys


DEFAULTS = {
    "caddy": "codestra-caddy-upstream-gateway",
    "kong": "codestra-kong-kong-gateway-1",
    "middleware": "codestra-middleware-integration-api-1",
    "redis": "codestra-redis-1",
}


def inspect(name: str) -> dict:
    result = subprocess.run(
        ["docker", "inspect", name], capture_output=True, text=True, check=False
    )
    if result.returncode:
        raise RuntimeError(f"container unavailable: {name}")
    return json.loads(result.stdout)[0]


def networks(container: dict) -> set[str]:
    return set(container["NetworkSettings"]["Networks"])


def healthy(container: dict) -> bool:
    state = container["State"]
    return state.get("Running") is True and state.get("Health", {}).get("Status") == "healthy"


def main() -> int:
    parser = argparse.ArgumentParser()
    for role, default in DEFAULTS.items():
        parser.add_argument(f"--{role}", default=default)
    args = parser.parse_args()
    names = {role: getattr(args, role) for role in DEFAULTS}
    try:
        containers = {role: inspect(name) for role, name in names.items()}
    except (RuntimeError, json.JSONDecodeError) as error:
        print(f"RUNTIME_INTEGRATION=FAIL reason={error}")
        return 2

    failures: list[str] = []
    for role, container in containers.items():
        if not healthy(container):
            failures.append(f"{role}_not_healthy")

    required = {
        "caddy_kong": ("caddy", "kong", "codestra_edge"),
        "kong_middleware": ("kong", "middleware", "codestra_edge"),
        "kong_redis": ("kong", "redis", "codestra_backend"),
        "middleware_redis": ("middleware", "redis", "codestra_backend"),
    }
    for label, (left, right, required_network) in required.items():
        if not all(required_network in networks(containers[role]) for role in (left, right)):
            failures.append(f"{label}_missing_{required_network}")

    if failures:
        print("RUNTIME_INTEGRATION=FAIL reasons=" + ",".join(sorted(failures)))
        return 2
    print("RUNTIME_INTEGRATION=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
