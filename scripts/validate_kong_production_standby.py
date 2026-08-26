#!/usr/bin/env python3
"""Fail-closed static validator for the detached Kong standby package."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "deploy" / "kong-production-standby"


def load(relative: str):
    return json.loads((PACKAGE / relative).read_text())


def main() -> int:
    kong = load("kong/standby.json")
    client = load("keycloak/codestra-api.json")
    scopes = load("keycloak/scopes.json")
    errors: list[str] = []

    def require(value: bool, message: str) -> None:
        if not value:
            errors.append(message)

    require(kong["publicRoutesEnabled"] is False, "public routes must be false")
    require(kong["stagingHostname"] != kong["publicHostname"], "staging host must be isolated")
    require(kong["audience"] == client["clientId"] == scopes["audience"] == "codestra-api", "audience mismatch")
    require(kong["algorithms"] == ["RS256"], "only RS256 is approved")
    require(client["bearerOnly"] is True, "resource client must be bearer-only")
    for disabled in ("standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled"):
        require(client[disabled] is False, f"{disabled} must be false")
    require(client["redirectUris"] == [] and client["webOrigins"] == [], "resource client must have no redirects/origins")

    expected_paths = {"/v1/sms", "/v1/email", "/v1/webhooks/sms", "/v1/webhooks/email"}
    actual_paths = {service["path"] for service in kong["services"]}
    require(actual_paths == expected_paths, "standby path set mismatch")
    for service in kong["services"]:
        require(service["upstream"].startswith("no-delivery-middleware-fixture:"), f"unsafe upstream: {service['name']}")
        require(service["retries"] == 0, f"command retries must be zero: {service['name']}")
        require(service["bodyLimitBytes"] > 0, f"body limit missing: {service['name']}")
        require(service["ratePerMinute"] > 0, f"rate limit missing: {service['name']}")
    for family in ("scraper", "telephony"):
        gate = kong["gatedRouteFamilies"][family]
        require(gate["state"] == "BLOCKED" and gate["routeCreated"] is False, f"{family} must remain absent")

    forbidden_ports = {25, 2525, 2775, 8990, 5060, 5061, 4569, 5038, 8088, 4573, 5672, 6379, 5432, 3306, 9100}
    for service in kong["services"]:
        port = int(service["upstream"].rsplit(":", 1)[1])
        require(port not in forbidden_ports, f"native protocol upstream forbidden: {service['name']}")

    if errors:
        print("KONG_STANDBY_VALIDATION=FAIL")
        for error in errors:
            print(f"ERROR={error}")
        return 1
    print("KONG_STANDBY_VALIDATION=PASS")
    print("PUBLIC_KONG_ROUTES_ENABLED=NO")
    print("SCRAPER_ROUTE_CREATED=NO")
    print("TELEPHONY_ROUTE_CREATED=NO")
    return 0


if __name__ == "__main__":
    sys.exit(main())
