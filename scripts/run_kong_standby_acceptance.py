#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE = "http://127.0.0.1:8000"
HOST = "kong-standby.internal.codestra.agency"
MAX_RESPONSE = 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("acceptance_redirect_denied")


def open_request(request, timeout):
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(request, timeout=timeout)


def read_response(response):
    raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("acceptance_response_too_large")
    return raw


def credentials():
    client = Path("/etc/codestra/secrets/identity-platform/clients/codestra-cert-machine/client-id").read_text().strip()
    secret = Path("/etc/codestra/secrets/identity-platform/clients/codestra-cert-machine/client-secret").read_text().strip()
    key = Path("/etc/codestra/secrets/kong-standby/webhook-hmac").read_bytes().strip()
    if not client or not secret or len(key) < 32:
        raise ValueError("acceptance_credentials_missing")
    return client, secret, key


def token(client: str, secret: str) -> str:
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials", "client_id": client,
        "client_secret": secret,
        "scope": "codestra-api-audience sms.send email.send",
    }).encode()
    request = urllib.request.Request(
        "https://auth.codestra.co/realms/codestra/protocol/openid-connect/token",
        data=body, method="POST")
    with open_request(request, timeout=15) as response:
        value = json.loads(read_response(response))
        access = value.get("access_token") if isinstance(value, dict) else None
        if not isinstance(access, str) or not access or len(access) > 16384 or any(c.isspace() for c in access):
            raise ValueError("invalid_acceptance_token")
        return access


def call(path: str, body: bytes, headers: dict[str, str]) -> tuple[int, bytes]:
    all_headers = {"Host": HOST, **headers}
    request = urllib.request.Request(BASE + path, data=body, headers=all_headers, method="POST")
    try:
        with open_request(request, timeout=10) as response:
            return response.status, read_response(response)
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, read_response(exc)


def expect(name: str, expected: int, actual: tuple[int, bytes]):
    if actual[0] != expected:
        raise ValueError(f"{name}: unexpected HTTP status")
    if expected == 200:
        value = json.loads(actual[1])
        if not isinstance(value, dict) or value.get("status") != "accepted_mock" or value.get("external_action") is not False:
            raise ValueError(f"{name}: non-mock response")
    print(f"{name}=PASS")


def run():
    client, secret, hmac_key = credentials()
    access = token(client, secret)
    session = uuid.uuid4().hex
    auth = {"Authorization": "Bearer " + access, "Content-Type": "application/json", "Idempotency-Key": "standby-" + session}
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
    if first[1] != replay[1]:
        raise ValueError("IDEMPOTENCY_REPLAY_TEST: response mismatch")
    expect("IDEMPOTENCY_CONFLICT_TEST", 409, call("/v1/sms", b'{"tenant":"cert-customer-a","fixture":false}', auth))
    expect("EMAIL_STAGING_AUTHORIZATION", 200, call("/v1/email", payload, {**auth, "Idempotency-Key": "email-1"}))
    expect("INVALID_CONTENT_TYPE_REJECTION", 415, call("/v1/email", payload, {**auth, "Content-Type": "text/plain", "Idempotency-Key": "email-content"}))
    expect("REQUEST_SIZE_REJECTION", 413, call("/v1/sms", b"x" * 70000, {**auth, "Idempotency-Key": "oversize"}))

    now = str(int(time.time()))
    nonce = str(time.time_ns())
    event = "standby-event-" + nonce + "-1"
    webhook_body = b'{"fixture":true}'
    signature = hmac.new(hmac_key, f"v1.{now}.{event}.".encode() + webhook_body, hashlib.sha256).hexdigest()
    webhook_headers = {"Content-Type": "application/json", "X-Signature-Version": "v1", "X-Key-ID": "standby-v1", "X-Timestamp": now, "X-Event-ID": event, "X-Signature": signature}
    expect("SMS_WEBHOOK_HMAC", 200, call("/v1/webhooks/sms", webhook_body, webhook_headers))
    expect("DUPLICATE_EVENT_REJECTION", 409, call("/v1/webhooks/sms", webhook_body, webhook_headers))
    expect("WRONG_HMAC_REJECTION", 401, call("/v1/webhooks/email", webhook_body, {**webhook_headers, "X-Event-ID": "standby-event-" + nonce + "-2", "X-Signature": "0" * 64}))
    stale = str(int(time.time()) - 600)
    stale_event = "standby-event-" + nonce + "-3"
    stale_sig = hmac.new(hmac_key, f"v1.{stale}.{stale_event}.".encode() + webhook_body, hashlib.sha256).hexdigest()
    expect("STALE_TIMESTAMP_REJECTION", 401, call("/v1/webhooks/email", webhook_body, {**webhook_headers, "X-Timestamp": stale, "X-Event-ID": stale_event, "X-Signature": stale_sig}))
    print("STANDBY_MOCK_RESPONSES=PASS")
    print("EXTERNAL_EFFECT_COUNTERS=NOT_MEASURED")
    print("FULL_RUNTIME_CERTIFICATION=NOT_ESTABLISHED")


def main():
    parser = argparse.ArgumentParser(description="Run authorized private mock-standby acceptance checks.")
    parser.add_argument("--execute-isolated-staging", action="store_true")
    args = parser.parse_args()
    if not args.execute_isolated_staging:
        print("STANDBY_ACCEPTANCE=NOT_RUN")
        return 2
    try:
        run()
        return 0
    except (OSError, ValueError, TypeError, KeyError, urllib.error.URLError):
        print("STANDBY_ACCEPTANCE=FAIL")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
