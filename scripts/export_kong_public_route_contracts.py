#!/usr/bin/env python3
"""Export sanitized exact evidence for public Kong routes not yet source-authorized.

This command is read-only. It never follows Kong pagination to another origin,
never reads consumer credentials, and never emits secret-bearing plugin values.
The output is evidence for a later reviewed source contract; it is not activation
authority by itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen


SENSITIVE_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "cookie",
    "password",
    "private_key",
    "proxy_authorization",
    "rsa_private_key",
    "secret",
    "set_cookie",
    "shared_secret",
    "token",
    "x_api_key",
    "x_auth_token",
}
SENSITIVE_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_cookie",
    "_password",
    "_private_key",
    "_secret",
    "_token",
)
SENSITIVE_HEADER_NAMES = {
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[\s,;])(?:api[-_ ]?key|authorization|client_secret|cookie|"
    r"password|private_key|proxy-authorization|secret|set-cookie|shared_secret|"
    r"token|x-api-key|x-auth-token)\s*[:=]"
)
BEARER_VALUE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
PRIVATE_KEY_MARKER = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


def request(base: str, path: str) -> dict:
    url = path if path.startswith(("http://", "https://")) else base.rstrip("/") + path
    with urlopen(Request(url, method="GET"), timeout=10) as response:
        raw = response.read()
        return json.loads(raw) if raw else {}


def safe_next(base: str, value: str | None) -> str | None:
    if not value:
        return None
    base_url = urlsplit(base)
    resolved = urlsplit(urljoin(base.rstrip("/") + "/", value))
    if (resolved.scheme, resolved.netloc) != (base_url.scheme, base_url.netloc):
        raise RuntimeError("unsafe Kong pagination URL")
    return resolved.geturl()


def all_rows(base: str, path: str) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    next_url: str | None = path
    while next_url:
        if next_url in seen:
            raise RuntimeError("Kong pagination loop detected")
        seen.add(next_url)
        page = request(base, next_url)
        rows.extend(page.get("data", []))
        next_url = safe_next(base, page.get("next"))
    return rows


def sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    if normalized in {"secret_is_base64", "key_claim_name"}:
        return False
    return normalized in SENSITIVE_KEYS or normalized.endswith(SENSITIVE_SUFFIXES)


def redacted(value) -> dict[str, object]:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return {"redacted": True, "sha256": hashlib.sha256(payload).hexdigest()}


def sensitive_scalar(value: object, key: str) -> bool:
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if PRIVATE_KEY_MARKER.search(stripped) or BEARER_VALUE.search(stripped):
        return True
    if SENSITIVE_ASSIGNMENT.search(stripped):
        return True
    if ":" in stripped:
        header_name = stripped.split(":", 1)[0].strip().lower()
        if header_name in SENSITIVE_HEADER_NAMES:
            return True
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in {"headers", "header", "add_headers", "replace_headers", "append_headers"}:
        header_name = stripped.split(":", 1)[0].strip().lower()
        if header_name in SENSITIVE_HEADER_NAMES:
            return True
    parsed = urlsplit(stripped)
    return bool(parsed.scheme and (parsed.username or parsed.password))


def sanitize(value, key: str = ""):
    if sensitive_key(key):
        return redacted(value)
    if isinstance(value, dict):
        return {name: sanitize(item, name) for name, item in sorted(value.items())}
    if isinstance(value, list):
        return [sanitize(item, key) for item in value]
    if sensitive_scalar(value, key):
        return redacted(value)
    return value


def canonical_sha256(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def one(rows: list[dict], label: str) -> dict:
    if len(rows) != 1:
        raise RuntimeError(f"expected exactly one {label}")
    return rows[0]


def route_record(
    admin: str,
    route: dict,
    service_by_id: dict[str, dict],
) -> dict:
    service = service_by_id[route["service"]["id"]]
    plugins = [
        plugin
        for plugin in all_rows(admin, f"/routes/{route['id']}/plugins?size=1000")
        if plugin.get("enabled")
    ]
    by_name: dict[str, list[dict]] = {}
    for plugin in plugins:
        by_name.setdefault(plugin["name"], []).append(plugin)
    duplicates = sorted(name for name, values in by_name.items() if len(values) != 1)
    if duplicates:
        raise RuntimeError(f"duplicate enabled route plugins: {duplicates}")
    plugin_records = []
    for name in sorted(by_name):
        config = sanitize(by_name[name][0].get("config", {}))
        plugin_records.append(
            {
                "name": name,
                "config": config,
                "sanitized_config_sha256": canonical_sha256(config),
            }
        )
    return {
        "name": route.get("name"),
        "hosts": sorted(route.get("hosts") or []),
        "paths": sorted(route.get("paths") or []),
        "methods": sorted(route.get("methods") or []),
        "protocols": sorted(route.get("protocols") or []),
        "strip_path": route.get("strip_path"),
        "preserve_host": route.get("preserve_host"),
        "https_redirect_status_code": route.get("https_redirect_status_code"),
        "headers": sanitize(route.get("headers") or {}, "headers"),
        "snis": sorted(route.get("snis") or []),
        "sources": route.get("sources") or [],
        "destinations": route.get("destinations") or [],
        "service": {
            "name": service.get("name"),
            "protocol": service.get("protocol"),
            "host": service.get("host"),
            "port": service.get("port"),
            "path": service.get("path"),
            "retries": service.get("retries"),
            "connect_timeout": service.get("connect_timeout"),
            "read_timeout": service.get("read_timeout"),
            "write_timeout": service.get("write_timeout"),
        },
        "plugins": plugin_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--admin-url", required=True)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("config/kong-canonical-middleware-routes.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest_bytes = args.manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    names = manifest.get("unverifiedExistingRouteNames", [])
    if not names:
        raise RuntimeError("no unverified public route names are declared")
    if len(names) != len(set(names)):
        raise RuntimeError("duplicate unverified public route names")

    routes = all_rows(args.admin_url, "/routes?size=1000")
    services = {
        service["id"]: service
        for service in all_rows(args.admin_url, "/services?size=1000")
    }
    records = []
    for name in names:
        route = one(
            [item for item in routes if item.get("name") == name],
            f"route named {name}",
        )
        public_hosts = {manifest["canonicalHost"], manifest["legacyHost"]}
        if not public_hosts.intersection(route.get("hosts") or []):
            raise RuntimeError(f"declared unverified route is not public: {name}")
        records.append(route_record(args.admin_url, route, services))

    document = {
        "schema": "codestra.kong.public-route-evidence.v1",
        "mode": "read-only",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "admin_origin": urlsplit(args.admin_url)._replace(path="", query="", fragment="").geturl(),
        "credentials_exported": False,
        "routes": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(f"UNVERIFIED_PUBLIC_ROUTE_EVIDENCE={len(records)}")
    print("CREDENTIALS_EXPORTED=NO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
