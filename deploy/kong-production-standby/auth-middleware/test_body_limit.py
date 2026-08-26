from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("body_limit.py")
SPEC = importlib.util.spec_from_file_location("body_limit_under_test", MODULE_PATH)
BODY_LIMIT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(BODY_LIMIT)


async def accepted_app(_scope, receive, send):
    body = bytearray()
    while True:
        message = await receive()
        body.extend(message.get("body", b""))
        if not message.get("more_body", False):
            break
    response = bytes(body)
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": response})


def invoke(chunks, *, limit=8, content_length=None, extra_headers=()):
    frames = [
        {"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1}
        for index, chunk in enumerate(chunks)
    ] or [{"type": "http.request", "body": b"", "more_body": False}]
    headers = list(extra_headers)
    if content_length is not None:
        headers.append((b"content-length", content_length))
    sent = []

    async def receive():
        return frames.pop(0)

    async def send(message):
        sent.append(message)

    middleware = BODY_LIMIT.RequestBodyLimitMiddleware(accepted_app, limit)
    asyncio.run(middleware({"type": "http", "headers": headers}, receive, send))
    return sent


@pytest.mark.parametrize(
    ("length", "status"),
    [(b"7", 200), (b"8", 200), (b"9", 413), (b"999999999999999999999999", 413)],
)
def test_content_length_boundaries(length, status):
    body = b"x" * min(int(length), 8)
    assert invoke([body], content_length=length)[0]["status"] == status


@pytest.mark.parametrize("length", [b"", b"-1", b"+1", b"1.0", b"garbage", b" 8"])
def test_malformed_content_length_fails_closed(length):
    assert invoke([b""], content_length=length)[0]["status"] == 400


def test_duplicate_content_length_fails_closed():
    headers = ((b"content-length", b"1"), (b"content-length", b"1"))
    assert invoke([b"x"], extra_headers=headers)[0]["status"] == 400


@pytest.mark.parametrize(
    ("chunks", "status"),
    [
        ([b"ab", b"cd"], 200),
        ([b"abcd", b"efgh"], 200),
        ([b"abcd", b"efghi"], 413),
        ([b"123456789"], 413),
        ([], 200),
    ],
)
def test_missing_content_length_and_multiframe_limits(chunks, status):
    assert invoke(chunks)[0]["status"] == status


def test_valid_body_is_replayed_unchanged():
    response = invoke([b'{"a":', b"1}"])
    assert response[0]["status"] == 200
    assert response[1]["body"] == b'{"a":1}'


@pytest.mark.parametrize("encoding", [b"gzip", b"deflate", b"br", b"compress"])
def test_unsupported_content_encoding_is_rejected(encoding):
    response = invoke([b"compressed"], extra_headers=((b"content-encoding", encoding),))
    assert response[0]["status"] == 415


def test_invalid_configuration_fails_startup(monkeypatch):
    for value in ("0", "-1", "65537", "unbounded", ""):
        monkeypatch.setenv("AUTH_MIDDLEWARE_MAX_BODY_BYTES", value)
        with pytest.raises(RuntimeError):
            BODY_LIMIT.configured_max_body_bytes()


def test_default_configuration_is_strictest_kong_limit(monkeypatch):
    monkeypatch.delenv("AUTH_MIDDLEWARE_MAX_BODY_BYTES", raising=False)
    assert BODY_LIMIT.configured_max_body_bytes() == 65_536
