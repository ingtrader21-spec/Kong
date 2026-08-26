from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException


CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
LEGACY_ISSUER = "https://auth.codestra" + ".agency/realms/codestra"
AUDIENCE = "codestra-api"
AUTHORIZED_PARTY = "codestra-cert-machine"
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def load_app():
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    database = root / "database-url"
    hmac_key = root / "hmac"
    database.write_text("postgresql://unused")
    hmac_key.write_bytes(b"test-only-hmac-key")
    os.environ["DATABASE_URL_FILE"] = str(database)
    os.environ["WEBHOOK_HMAC_FILE"] = str(hmac_key)
    os.environ["STATE_DB"] = str(root / "state.sqlite3")
    spec = importlib.util.spec_from_file_location("standby_auth_under_test", Path(__file__).with_name("app.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module._test_temp = temp
    module.jwks = SimpleNamespace(get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=PRIVATE_KEY.public_key()))
    module.psycopg.connect = lambda _url: FakeConnection()
    return module


class FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, _query, _params):
        pass

    def fetchone(self):
        return ("cert-customer-a", "active", ["sms.send", "email.send"])


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return FakeCursor()


APP = load_app()


def token(**overrides):
    now = int(time.time())
    claims = {
        "iss": CANONICAL_ISSUER,
        "aud": AUDIENCE,
        "azp": AUTHORIZED_PARTY,
        "sub": "certifier",
        "scope": "sms.send email.send",
        "iat": now,
        "nbf": now,
        "exp": now + 300,
        "jti": "test-jti",
    }
    claims.update(overrides)
    for key in [key for key, value in claims.items() if value is None]:
        del claims[key]
    return jwt.encode(claims, PRIVATE_KEY, algorithm="RS256", headers={"kid": "test-key"})


def request(encoded):
    return SimpleNamespace(headers={"authorization": "Bearer " + encoded})


def assert_rejected(encoded):
    with pytest.raises(HTTPException) as exc:
        APP.identity(request(encoded), "sms.send")
    assert exc.value.status_code == 401


def test_canonical_token_accepted():
    assert APP.identity(request(token()), "sms.send")["tenant"] == "cert-customer-a"


@pytest.mark.parametrize(
    "claims",
    [
        {"iss": LEGACY_ISSUER},
        {"iss": "https://wrong.example/realms/codestra"},
        {"iss": None},
        {"aud": "wrong-audience"},
        {"azp": "wrong-client"},
        {"exp": int(time.time()) - 1},
        {"nbf": int(time.time()) + 300},
    ],
)
def test_claim_negative_matrix(claims):
    assert_rejected(token(**claims))


def test_bad_signature_rejected():
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    encoded = jwt.encode(
        {"iss": CANONICAL_ISSUER, "aud": AUDIENCE, "azp": AUTHORIZED_PARTY,
         "sub": "certifier", "scope": "sms.send", "iat": now, "exp": now + 300},
        other_key, algorithm="RS256", headers={"kid": "test-key"})
    assert_rejected(encoded)


def test_unknown_kid_rejected():
    original = APP.jwks
    APP.jwks = SimpleNamespace(get_signing_key_from_jwt=lambda _token: (_ for _ in ()).throw(jwt.PyJWKClientError("unknown kid")))
    try:
        assert_rejected(token())
    finally:
        APP.jwks = original


def test_missing_scope_rejected_without_weakening_identity_checks():
    with pytest.raises(HTTPException) as exc:
        APP.identity(request(token(scope="email.send")), "sms.send")
    assert exc.value.status_code == 403


def test_canonical_jwks_is_the_only_key_endpoint():
    assert APP.ISSUER == CANONICAL_ISSUER
    assert APP.JWKS == CANONICAL_ISSUER + "/protocol/openid-connect/certs"
    assert "agency" not in APP.JWKS
