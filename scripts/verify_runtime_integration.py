#!/usr/bin/env python3
"""Fail-closed, secret-free verification of the deployed gateway topology."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys


DEFAULTS = {
    "caddy": "codestra-caddy-upstream-gateway",
    "kong": "codestra-kong-kong-gateway-1",
    "middleware": "codestra-appolon-middleware-integration-api-1",
    "redis": "codestra-redis-1",
}


def inspect(name: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
        raise RuntimeError("invalid_container_name")
    template = '{"State":{{json .State}},"NetworkSettings":{"Networks":{{json .NetworkSettings.Networks}}}}'
    result = subprocess.run(
        ["docker", "--host", "unix:///var/run/docker.sock", "inspect", "--format", template, name],
        capture_output=True, text=True, check=False, timeout=10
    )
    if result.returncode:
        raise RuntimeError("container_unavailable")
    value = json.loads(result.stdout)
    if not isinstance(value, dict) or not isinstance(value.get("State"), dict):
        raise RuntimeError("invalid_container_readback")
    if not isinstance(value["State"].get("Health", {}), dict):
        raise RuntimeError("invalid_container_readback")
    network_settings = value.get("NetworkSettings")
    if not isinstance(network_settings, dict):
        raise RuntimeError("invalid_container_readback")
    attached = network_settings.get("Networks")
    if not isinstance(attached, dict) or not all(
        isinstance(name, str) and name and isinstance(endpoint, dict)
        for name, endpoint in attached.items()
    ):
        raise RuntimeError("invalid_container_readback")
    return value


def networks(container: dict) -> set[str]:
    return set(container["NetworkSettings"]["Networks"])


def healthy(container: dict) -> bool:
    state = container["State"]
    return (
        state.get("Running") is True
        and state.get("Paused") is False
        and state.get("Restarting") is False
        and state.get("Health", {}).get("Status") == "healthy"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    for role, default in DEFAULTS.items():
        parser.add_argument(f"--{role}", default=default)
    args = parser.parse_args()
    names = {role: getattr(args, role) for role in DEFAULTS}
    containers = {}
    for role, name in names.items():
        try:
            containers[role] = inspect(name)
        except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
            print(f"RUNTIME_INTEGRATION=FAIL reason={role}_container_readback_unavailable")
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
