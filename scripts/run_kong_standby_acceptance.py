#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8000"
HOST = "kong-standby.internal.codestra.agency"
CLIENT_ID = Path("/etc/codestra/secrets/identity-platform/clients/codestra-cert-machine/client-id").read_text().strip()
CLIENT_SECRET = Path("/etc/codestra/secrets/identity-platform/clients/codestra-cert-machine/client-secret").read_text().strip()
HMAC_KEY = Path("/etc/codestra/secrets/kong-standby/webhook-hmac").read_bytes().strip()


def token() -> str:
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "codestra-api-audience sms.send email.send",
    }).encode()
    request = urllib.request.Request(
        "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token",
        data=body, method="POST")
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)["access_token"]


def call(path: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    all_headers = {"Host": HOST, **headers}
    request = urllib.request.Request(BASE + path, data=body, headers=all_headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def expect(name: str, expected: int, actual: tuple[int, bytes]):
    assert actual[0] == expected, f"{name}: expected {expected}, got {actual[0]} {actual[1][:200]!r}"
    print(f"{name}=PASS")


def main():
    access = token()
    auth = {"Authorization": "Bearer " + access, "Content-Type": "application/json", "Idempotency-Key": "standby-acceptance-1"}
    payload = json.dumps({"tenant": "cert-customer-a", "fixture": True}, separators=(",", ":")).encode()
    expect("MISSING_TOKEN_REJECTION", 401, call("/v1/sms", payload, {"Content-Type": "application/json", "Idempotency-Key": "missing"}))
    expect("MALFORMED_TOKEN_REJECTION", 401, call("/v1/sms", payload, {"Authorization": "Bearer not-a-jwt", "Content-Type": "application/json", "Idempotency-Key": "bad"}))
    # Kong removes spoofable identity headers before the middleware sees them;
    # the valid bearer request remains authorized from canonical identity data.
    expect("SPOOFED_HEADER_SANITIZATION", 200, call("/v1/sms", payload, {**auth, "X-Codestra-Tenant": "attacker-value"}))
    expect("CROSS_TENANT_REJECTION", 404, call("/v1/sms", b'{"tenant":"cert-customer-b","fixture":true}', {**auth, "Idempotency-Key": "cross"}))
    first = call("/v1/sms", payload, auth)
    expect("SMS_STAGING_AUTHORIZATION", 200, first)
    replay = call("/v1/sms", payload, auth)
    expect("IDEMPOTENCY_REPLAY_TEST", 200, replay)
    assert first[1] == replay[1]
    expect("IDEMPOTENCY_CONFLICT_TEST", 409, call("/v1/sms", b'{"tenant":"cert-customer-a","fixture":false}', auth))
    expect("EMAIL_STAGING_AUTHORIZATION", 200, call("/v1/email", payload, {**auth, "Idempotency-Key": "email-1"}))
    expect("INVALID_CONTENT_TYPE_REJECTION", 415, call("/v1/email", payload, {**auth, "Content-Type": "text/plain", "Idempotency-Key": "email-content"}))
    expect("REQUEST_SIZE_REJECTION", 413, call("/v1/sms", b"x" * 70000, {**auth, "Idempotency-Key": "oversize"}))

    now = str(int(time.time()))
    nonce = str(time.time_ns())
    event = "standby-event-" + nonce + "-1"
    webhook_body = b'{"fixture":true}'
    signature = hmac.new(HMAC_KEY, f"v1.{now}.{event}.".encode() + webhook_body, hashlib.sha256).hexdigest()
    webhook_headers = {"Content-Type": "application/json", "X-Signature-Version": "v1", "X-Key-ID": "standby-v1", "X-Timestamp": now, "X-Event-ID": event, "X-Signature": signature}
    expect("SMS_WEBHOOK_HMAC", 200, call("/v1/webhooks/sms", webhook_body, webhook_headers))
    expect("DUPLICATE_EVENT_REJECTION", 409, call("/v1/webhooks/sms", webhook_body, webhook_headers))
    expect("WRONG_HMAC_REJECTION", 401, call("/v1/webhooks/email", webhook_body, {**webhook_headers, "X-Event-ID": "standby-event-" + nonce + "-2", "X-Signature": "0" * 64}))
    stale = str(int(time.time()) - 600)
    stale_event = "standby-event-" + nonce + "-3"
    stale_sig = hmac.new(HMAC_KEY, f"v1.{stale}.{stale_event}.".encode() + webhook_body, hashlib.sha256).hexdigest()
    expect("STALE_TIMESTAMP_REJECTION", 401, call("/v1/webhooks/email", webhook_body, {**webhook_headers, "X-Timestamp": stale, "X-Event-ID": stale_event, "X-Signature": stale_sig}))
    print("EXTERNAL_ACTIONS=0")


if __name__ == "__main__":
    main()
