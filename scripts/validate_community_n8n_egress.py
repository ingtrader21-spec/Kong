#!/usr/bin/env python3
import ipaddress
import json
import os
from pathlib import Path

root = Path(__file__).resolve().parents[1]
contract = json.loads((root / "config/kong-community-n8n-egress.v1.json").read_text())
service = contract["service"]
route = contract["route"]

assert contract["status"] == "PROPOSED_NOT_APPLIED"
assert contract["public_endpoint"] == "https://api.codestra.co/v1/integrations/n8n"
assert service["protocol"] == "https" and service["port"] == 443 and service["tls_verify"] is True
assert service["ip_literal_allowed"] is False
assert route["protocols"] == ["https"] and route["methods"] == ["GET", "POST"]
assert route["http_redirect_status"] in (301, 308)
assert set(contract["plugins"]["names"]) == {
    "correlation-id", "request-transformer", "request-size-limiting", "rate-limiting"
}
assert contract["identity"]["middleware_revalidates_token"] is True
assert contract["safety"]["external_effects_enabled"] is False

host = os.environ.get("MIDDLEWARE_TLS_HOST")
if host:
    assert not host.startswith("http://") and not host.startswith("https://")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise AssertionError("MIDDLEWARE_TLS_HOST must be a DNS name, not an IP literal")

print("KONG_COMMUNITY_N8N_EGRESS=PASS")
