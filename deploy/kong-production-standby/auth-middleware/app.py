from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path

import jwt
import psycopg
from fastapi import FastAPI, Header, HTTPException, Request
from jwt import PyJWKClient

from body_limit import RequestBodyLimitMiddleware, configured_max_body_bytes

ISSUER = "https://auth.codestra.co/realms/codestra"
AUDIENCE = "codestra-api"
AUTHORIZED_PARTY = "codestra-cert-machine"
JWKS = ISSUER + "/protocol/openid-connect/certs"
DATABASE_URL = Path(os.environ["DATABASE_URL_FILE"]).read_text().strip()
HMAC_KEY = Path(os.environ["WEBHOOK_HMAC_FILE"]).read_bytes().strip()
TRUSTED_HEADERS = {"x-codestra-subject", "x-codestra-tenant", "x-codestra-roles", "x-codestra-scopes", "x-authenticated-user"}
SCOPES = {"sms": "sms.send", "email": "email.send"}
jwks = PyJWKClient(JWKS, cache_keys=True, lifespan=300)
STATE_DB = os.environ.get("STATE_DB", "/data/state.sqlite3")
IDEMPOTENCY_RETENTION_SECONDS = 30 * 24 * 60 * 60


def state() -> sqlite3.Connection:
    conn = sqlite3.connect(STATE_DB, timeout=5, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE IF NOT EXISTS idempotency (tenant TEXT, family TEXT, key TEXT, digest TEXT, response TEXT, created_at INTEGER, PRIMARY KEY(tenant,family,key))")
    conn.execute("CREATE TABLE IF NOT EXISTS webhook_replay (event_id TEXT PRIMARY KEY, accepted_at INTEGER)")
    return conn


state().close()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_bytes=configured_max_body_bytes(),
)


def deny(code: int, reason: str):
    raise HTTPException(code, reason)


def identity(request: Request, required_scope: str) -> dict:
    if any(name in request.headers for name in TRUSTED_HEADERS):
        deny(403, "spoofed_identity_header")
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        deny(401, "missing_token")
    token = auth[7:]
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not header.get("kid"):
            deny(401, "algorithm_or_kid_denied")
        claims = jwt.decode(token, jwks.get_signing_key_from_jwt(token).key,
                            algorithms=["RS256"], issuer=ISSUER, audience=AUDIENCE,
                            options={"require": ["iss", "aud", "azp", "sub", "iat", "exp"]}, leeway=0)
        if claims["azp"] != AUTHORIZED_PARTY:
            deny(401, "authorized_party_denied")
        if claims["exp"] <= claims["iat"]:
            deny(401, "token_lifetime_denied")
    except HTTPException:
        raise
    except Exception:
        deny(401, "invalid_token")
    scopes = set(str(claims.get("scope", "")).split())
    if required_scope not in scopes:
        deny(403, "scope_denied")
    with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
        cur.execute("SELECT tenant_key,status,allowed_scopes FROM oidc_tenant_registry WHERE issuer=%s AND subject=%s", (ISSUER, claims["sub"]))
        row = cur.fetchone()
    if not row or row[1] != "active" or required_scope not in set(row[2] or []):
        deny(403, "identity_or_scope_unmapped")
    return {"subject": claims["sub"], "tenant": row[0], "scope": required_scope}


@app.get("/health")
def health():
    try:
        with psycopg.connect(DATABASE_URL) as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchone()[0] == 1
        db = state()
        db.execute("SELECT 1").fetchone()
        db.close()
    except Exception:
        deny(503, "dependency_unavailable")
    return {"status": "healthy", "mode": "mock-only", "external_actions": False}


@app.post("/v1/{family}")
async def command(family: str, request: Request, idempotency_key: str | None = Header(None)):
    if family not in SCOPES:
        deny(404, "not_found")
    if not idempotency_key or len(idempotency_key) > 128:
        deny(400, "idempotency_key_required")
    context = identity(request, SCOPES[family])
    body = await request.body()
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        deny(415, "content_type_denied")
    try:
        payload = json.loads(body)
    except Exception:
        deny(400, "malformed_json")
    if not isinstance(payload, dict):
        deny(400, "json_object_required")
    if payload.get("tenant") != context["tenant"]:
        deny(404, "tenant_not_found")
    digest = hashlib.sha256(body).hexdigest()
    key = (context["tenant"], family, idempotency_key)
    result = {"status": "accepted_mock", "external_action": False, "request_digest": digest[:16]}
    db = state()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM idempotency WHERE created_at < ?", (int(time.time()) - IDEMPOTENCY_RETENTION_SECONDS,))
        row = db.execute("SELECT digest,response FROM idempotency WHERE tenant=? AND family=? AND key=?", key).fetchone()
        if row:
            db.execute("COMMIT")
            if row[0] != digest:
                deny(409, "idempotency_conflict")
            return json.loads(row[1])
        db.execute("INSERT INTO idempotency VALUES (?,?,?,?,?,?)", (*key, digest, json.dumps(result, separators=(",", ":")), int(time.time())))
        db.execute("COMMIT")
    except HTTPException:
        raise
    except Exception:
        db.execute("ROLLBACK")
        deny(503, "idempotency_unavailable")
    finally:
        db.close()
    return result


@app.post("/v1/webhooks/{family}")
async def webhook(family: str, request: Request,
                  x_signature_version: str | None = Header(None),
                  x_key_id: str | None = Header(None),
                  x_timestamp: str | None = Header(None),
                  x_event_id: str | None = Header(None),
                  x_signature: str | None = Header(None)):
    if family not in {"sms", "email"}:
        deny(404, "not_found")
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        deny(415, "content_type_denied")
    if x_signature_version != "v1" or not all((x_key_id, x_timestamp, x_event_id, x_signature)):
        deny(401, "signature_missing")
    try:
        timestamp = int(x_timestamp)
    except ValueError:
        deny(401, "timestamp_invalid")
    now = int(time.time())
    if abs(now - timestamp) > 300:
        deny(401, "timestamp_stale")
    body = await request.body()
    signed = f"v1.{x_timestamp}.{x_event_id}.".encode() + body
    expected = hmac.new(HMAC_KEY, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        deny(401, "signature_invalid")
    db = state()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM webhook_replay WHERE accepted_at < ?", (now - 300,))
        db.execute("INSERT INTO webhook_replay(event_id,accepted_at) VALUES (?,?)", (x_event_id, now))
        db.execute("COMMIT")
    except sqlite3.IntegrityError:
        db.execute("ROLLBACK")
        deny(409, "event_replay")
    except Exception:
        db.execute("ROLLBACK")
        deny(503, "replay_cache_unavailable")
    finally:
        db.close()
    return {"status": "accepted_mock", "external_action": False}
