from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable
from typing import Any


DEFAULT_MAX_BODY_BYTES = 65_536
# The strictest approved Kong route limit is the largest value an operator may
# configure here.  This prevents a typo from silently widening direct access.
MAX_CONFIGURABLE_BODY_BYTES = 131_072


def configured_max_body_bytes() -> int:
    raw = os.environ.get("AUTH_MIDDLEWARE_MAX_BODY_BYTES", str(DEFAULT_MAX_BODY_BYTES))
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise RuntimeError("AUTH_MIDDLEWARE_MAX_BODY_BYTES must be an integer") from exc
    if not 1 <= value <= MAX_CONFIGURABLE_BODY_BYTES:
        raise RuntimeError(
            f"AUTH_MIDDLEWARE_MAX_BODY_BYTES must be between 1 and "
            f"{MAX_CONFIGURABLE_BODY_BYTES}"
        )
    return value


def _error_response(status: int, detail: str) -> tuple[dict[str, Any], dict[str, Any]]:
    body = json.dumps({"detail": detail}, separators=(",", ":")).encode()
    return (
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        },
        {"type": "http.response.body", "body": body},
    )


class RequestBodyLimitMiddleware:
    """Pure ASGI body guard that never buffers more than the configured limit."""

    def __init__(self, app: Callable[..., Awaitable[None]], max_body_bytes: int) -> None:
        if not 1 <= max_body_bytes <= MAX_CONFIGURABLE_BODY_BYTES:
            raise ValueError("invalid request body limit")
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: dict[str, Any], receive: Callable[..., Awaitable[dict[str, Any]]], send: Callable[..., Awaitable[None]]) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers: dict[bytes, list[bytes]] = {}
        for name, value in scope.get("headers", []):
            headers.setdefault(name.lower(), []).append(value)

        encodings = headers.get(b"content-encoding", [])
        if encodings and any(value.strip().lower() not in {b"", b"identity"} for value in encodings):
            for message in _error_response(415, "content_encoding_denied"):
                await send(message)
            return

        lengths = headers.get(b"content-length", [])
        if lengths:
            if len(lengths) != 1 or not lengths[0].isdigit():
                for message in _error_response(400, "content_length_invalid"):
                    await send(message)
                return
            if int(lengths[0]) > self.max_body_bytes:
                for message in _error_response(413, "payload_too_large"):
                    await send(message)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_body_bytes:
                for response_message in _error_response(413, "payload_too_large"):
                    await send(response_message)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return {"type": "http.request", "body": b"", "more_body": False}
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, replay, send)
