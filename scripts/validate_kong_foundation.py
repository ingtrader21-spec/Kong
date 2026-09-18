#!/usr/bin/env python3
"""Validate the Kong API Gateway Control Plane V1 foundation registry.

The registry (``config/kong-gateway-foundation.v1.json``) is the reviewed
authority map for every Kong service, route and plugin declared anywhere in this
repository. It does not duplicate mutable match data; every route and service is
*bound* to the reviewed source that declares it, and this validator materializes
the match from that source and proves:

* every route in every reviewed source is registered (no undocumented routes);
* every registered binding still resolves and every DESIRED binding agrees with
  every other DESIRED binding on the fields both declare (contract drift);
* every OBSERVED (runtime readback) binding differs from the DESIRED state only
  where the registry declares the drift (runtime drift ledger);
* route precedence is deterministic under the Kong 3.x router priority model and
  every overlapping pair is declared with its expected winner;
* every gateway-architecture-debt finding the rules detect is explicitly accepted
  on the route or service that carries it, and canonical routes carry none;
* every route has an explicit authentication class, traffic class, lifecycle,
  activation state and disposition, and an unauthenticated route can only be an
  explicitly reasoned read-only PUBLIC route or BLOCKED;
* every plugin used by any source is governed, authentication plugins are never
  global, and claim guards run after an authentication plugin;
* the node configuration keeps Admin/Manager/Status private, trusts only the
  configured Caddy source, keeps TLS verification on and runs least-privilege;
* every ``{vault://env/...}`` reference used by the deployed candidate is declared
  in the runtime environment template.

Source-only. Nothing here contacts a Kong Admin API, Caddy, Keycloak, Middleware
or Redis, and nothing here can authorize a runtime apply.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parents[1]
FOUNDATION = ROOT / "config/kong-gateway-foundation.v1.json"
SCHEMA = "codestra.kong.gateway-foundation.v1"

MUTATION_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
READ_ONLY_METHODS = {"GET", "HEAD", "OPTIONS"}
ALL_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}
AUTHENTICATION_PLUGINS = {
    "openid-connect", "jwt", "key-auth", "mtls-auth", "hmac-auth", "basic-auth",
    "ip-restriction", "codestra-webhook-verifier", "codestra-authz",
}
CLAIM_GUARD_PLUGINS = {"post-function", "codestra-authz"}
KONG_DEFAULT_RETRIES = 5
KONG_DEFAULT_TIMEOUT_MS = 60000
IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
VAULT_ENV = re.compile(r"\{vault://env/([a-z0-9-]+)\}")


class FoundationError(ValueError):
    """A registry, source, boundary or drift check failed."""


# --------------------------------------------------------------------------- model


@dataclass(frozen=True)
class SourceRoute:
    source: str
    name: str
    hosts: tuple[str, ...] | None = None
    paths: tuple[str, ...] | None = None
    methods: tuple[str, ...] | None = None
    protocols: tuple[str, ...] | None = None
    strip_path: bool | None = None
    preserve_host: bool | None = None
    regex_priority: int = 0
    service_name: str | None = None
    upstream_protocol: str | None = None
    upstream_host: str | None = None
    upstream_port: int | None = None
    plugins: tuple[str, ...] | None = None
    rate_per_minute: int | None = None
    max_body_bytes: int | None = None
    required_scope: str | None = None
    audience: str | None = None
    issuer: str | None = None
    enabled: bool | None = None
    client_id: str | None = None

    def field_values(self) -> dict[str, Any]:
        return {
            "hosts": self.hosts, "paths": self.paths, "methods": self.methods,
            "protocols": self.protocols, "strip_path": self.strip_path,
            "preserve_host": self.preserve_host, "upstream_host": self.upstream_host,
            "upstream_port": self.upstream_port, "upstream_protocol": self.upstream_protocol,
            "plugins": self.plugins, "rate_per_minute": self.rate_per_minute,
            "max_body_bytes": self.max_body_bytes, "required_scope": self.required_scope,
            "audience": self.audience,
        }


@dataclass(frozen=True)
class SourceService:
    source: str
    name: str
    protocol: str | None = None
    host: str | None = None
    port: int | None = None
    connect_timeout: int | None = None
    read_timeout: int | None = None
    write_timeout: int | None = None
    retries: int | None = None
    plugins: tuple[str, ...] = ()
    carries_timeouts: bool = True
    carries_retries: bool = True

    def field_values(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol, "host": self.host, "port": self.port,
            "connect_timeout": self.connect_timeout, "read_timeout": self.read_timeout,
            "write_timeout": self.write_timeout, "retries": self.retries,
        }


@dataclass
class SourceDocument:
    path: str
    format: str
    routes: dict[str, SourceRoute] = field(default_factory=dict)
    services: dict[str, SourceService] = field(default_factory=dict)
    global_plugins: tuple[str, ...] = ()
    edge_paths: tuple[str, ...] = ()
    declared_status: str | None = None
    declared_environment: str | None = None
    issuer: str | None = None


# --------------------------------------------------------------------------- helpers


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _tuple(values: Any) -> tuple[Any, ...] | None:
    if values is None:
        return None
    if isinstance(values, (str, int)):
        values = [values]
    return tuple(values)


def _methods(values: Any) -> tuple[str, ...] | None:
    values = _tuple(values)
    return None if values is None else tuple(str(v).upper() for v in values)


def _mb(value: Any) -> int | None:
    return None if value is None else int(value) * 1024 * 1024


def _url_parts(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return parts.scheme, parts.hostname or "", port


def _issuer_realm(value: str | None) -> str | None:
    if not value:
        return None
    return value.split("/.well-known/")[0]


# --------------------------------------------------------------------------- loaders


def load_kong_declarative(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="kong-declarative")
    out.global_plugins = tuple(p["name"] for p in doc.get("plugins", []) or [])
    for svc in doc.get("services", []) or []:
        protocol, host, port = _url_parts(svc["url"])
        svc_plugins = tuple(p["name"] for p in svc.get("plugins", []) or [])
        out.services[svc["name"]] = SourceService(
            source=path, name=svc["name"], protocol=protocol, host=host, port=port,
            connect_timeout=svc.get("connect_timeout"), read_timeout=svc.get("read_timeout"),
            write_timeout=svc.get("write_timeout"), retries=svc.get("retries"), plugins=svc_plugins,
        )
        for route in svc.get("routes", []) or []:
            route_plugins = tuple(p["name"] for p in route.get("plugins", []) or [])
            issuer = None
            audience = None
            for plugin in svc.get("plugins", []) or []:
                if plugin.get("name") == "openid-connect":
                    issuer = _issuer_realm(plugin.get("config", {}).get("issuer"))
                    aud = plugin.get("config", {}).get("audience") or []
                    audience = aud[0] if len(aud) == 1 else None
            out.routes[route["name"]] = SourceRoute(
                source=path, name=route["name"], hosts=_tuple(route.get("hosts")),
                paths=_tuple(route.get("paths")), methods=_methods(route.get("methods")),
                protocols=_tuple(route.get("protocols")), strip_path=route.get("strip_path"),
                preserve_host=route.get("preserve_host"), regex_priority=route.get("regex_priority", 0) or 0,
                service_name=svc["name"], upstream_protocol=protocol, upstream_host=host, upstream_port=port,
                plugins=tuple(sorted(set(route_plugins) | set(svc_plugins) | set(out.global_plugins))),
                max_body_bytes=_declared_body_limit(route.get("plugins", []) or []),
                rate_per_minute=_declared_rate(list(route.get("plugins", []) or []) + list(svc.get("plugins", []) or [])),
                issuer=issuer, audience=audience, enabled=svc.get("enabled"),
            )
    return out


def _declared_body_limit(plugins: list[dict]) -> int | None:
    for plugin in plugins:
        if plugin.get("name") == "request-size-limiting":
            config = plugin.get("config", {})
            size = config.get("allowed_payload_size")
            unit = config.get("size_unit", "megabytes")
            if size is None:
                return None
            factor = {"bytes": 1, "kilobytes": 1024, "megabytes": 1024 * 1024}[unit]
            return int(size) * factor
    return None


def _declared_rate(plugins: list[dict]) -> int | None:
    for plugin in plugins:
        if plugin.get("name") == "rate-limiting":
            return plugin.get("config", {}).get("minute")
    return None


def load_production_inventory(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="production-route-inventory")
    out.declared_status = doc.get("status")
    for route in doc["routes"]:
        svc = route["service"]
        out.services.setdefault(svc["name"], SourceService(
            source=path, name=svc["name"], protocol=svc["protocol"], host=svc["host"], port=svc["port"],
            connect_timeout=svc.get("connect_timeout"), read_timeout=svc.get("read_timeout"),
            write_timeout=svc.get("write_timeout"), retries=svc.get("retries"), carries_retries=False,
        ))
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=_tuple(route["hosts"]), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=_tuple(route["protocols"]),
            strip_path=route["strip_path"], preserve_host=route["preserve_host"], service_name=svc["name"],
            upstream_protocol=svc["protocol"], upstream_host=svc["host"], upstream_port=svc["port"],
            plugins=tuple(sorted(route["plugins"])),
        )
    return out


def load_canonical_middleware_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="canonical-middleware-contract")
    for route in doc["contractRoutes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=_tuple(route["hosts"]), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=_tuple(route["protocols"]),
            strip_path=route["stripPath"], preserve_host=route["preserveHost"],
            upstream_protocol="http", upstream_host=route["serviceHost"], upstream_port=route["servicePort"],
            plugins=tuple(sorted(route["requiredPlugins"])),
        )
    for route in doc.get("routes", []):
        # The legacy block names only the shared-key auth marker, rate and body
        # limit; hosts and the full plugin set are observed through the inventory.
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], paths=(route["path"],), methods=_methods(route["methods"]),
            max_body_bytes=_mb(route.get("maxBodyMb")), rate_per_minute=route.get("ratePerMinute"),
        )
    return out


CALLBACK_PLUGINS = ("correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting")
CAMPAIGN_PLUGINS = ("correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting")
N8N_PLUGINS = ("correlation-id", "jwt", "post-function", "rate-limiting", "request-size-limiting")


def _service_from_contract(path: str, svc: dict) -> SourceService:
    return SourceService(
        source=path, name=svc["name"], protocol=svc.get("protocol"), host=svc.get("host"), port=svc.get("port"),
        connect_timeout=svc.get("connect_timeout", svc.get("connectTimeoutMs")),
        read_timeout=svc.get("read_timeout", svc.get("readTimeoutMs")),
        write_timeout=svc.get("write_timeout", svc.get("writeTimeoutMs")),
        retries=svc.get("retries"),
    )


def load_callback_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="callback-contract", issuer=doc["issuer"])
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=("http",), strip_path=route["strip_path"],
            preserve_host=True, service_name=svc["name"], upstream_protocol=svc["protocol"],
            upstream_host=svc["host"], upstream_port=svc["port"], plugins=CALLBACK_PLUGINS,
            rate_per_minute=route["ratePerMinute"], max_body_bytes=_mb(route["maxBodyMb"]),
            required_scope=route["requiredScope"], audience=doc["audience"], issuer=doc["issuer"],
        )
    return out


def load_campaign_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="campaign-contract", issuer=doc["issuer"])
    out.declared_environment = doc.get("environment")
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["method"]), protocols=("http",), strip_path=False, preserve_host=False,
            service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=svc["host"],
            upstream_port=svc["port"], plugins=CAMPAIGN_PLUGINS, rate_per_minute=route["rate_per_minute"],
            max_body_bytes=_mb(route["max_body_mb"]), required_scope=route["scope"],
            audience=doc["audience"], issuer=doc["issuer"],
        )
    return out


def load_intake_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="intake-contract")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=_tuple(route["paths"]),
            methods=_methods(route["methods"]), protocols=("http",), strip_path=route["stripPath"],
            preserve_host=route["preserveHost"], service_name=svc["name"], upstream_protocol=svc["protocol"],
            upstream_host=svc["host"], upstream_port=svc["port"], plugins=tuple(sorted(route["requiredPlugins"])),
            rate_per_minute=route["ratePerMinute"], max_body_bytes=_mb(route["maxBodyMb"]),
            required_scope=route["requiredScope"], audience=route["requiredClientId"],
            client_id=route["requiredClientId"],
        )
    return out


def load_n8n_control_plane_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="n8n-control-plane-contract", issuer=doc["issuer"])
    out.declared_environment = doc.get("environment")
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["method"]), protocols=("http",), strip_path=False, preserve_host=False,
            service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=svc["host"],
            upstream_port=svc["port"], plugins=N8N_PLUGINS, rate_per_minute=route["rate_per_minute"],
            max_body_bytes=_mb(route["max_body_mb"]), required_scope=route["scope"],
            audience=doc["audience"], issuer=doc["issuer"], enabled=svc.get("enabled"),
            client_id=doc["client_id"],
        )
    return out


def load_n8n_editor_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="n8n-editor-contract", issuer=doc["issuer"])
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services[svc["name"]] = _service_from_contract(path, svc)
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["methods"]), strip_path=route["strip_path"], preserve_host=route["preserve_host"],
            service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=svc["host"],
            upstream_port=svc["port"], rate_per_minute=route["rate_per_minute"],
            max_body_bytes=_mb(route["max_body_mb"]), issuer=doc["issuer"], enabled=svc.get("enabled"),
        )
    return out


def load_moneybee_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="moneybee-contract", issuer=doc["identity"]["issuer"])
    out.declared_status = doc.get("state")
    up = doc["upstream"]
    # Transport policy is owned by scripts/render_kong_moneybee_identity.py.
    out.services[up["serviceName"]] = SourceService(
        source=path, name=up["serviceName"], protocol=up["protocol"], host=up["host"], port=up["port"],
        connect_timeout=3000, read_timeout=30000, write_timeout=30000, retries=0,
    )
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["canonicalHost"],), paths=(route["path"],),
            methods=_methods(route["methods"]), service_name=up["serviceName"], upstream_protocol=up["protocol"],
            upstream_host=up["host"], upstream_port=up["port"], plugins=tuple(sorted(route["requiredPlugins"])),
            rate_per_minute=route["rateLimitPerMinute"], max_body_bytes=route["maxBodyBytes"],
            audience=doc["identity"]["requiredAudience"], issuer=doc["identity"]["issuer"],
            client_id=doc["identity"]["registrationClient"],
        )
    return out


def load_provider_control_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="provider-control-contract", issuer=doc["issuer"])
    out.declared_status = doc.get("status")
    svc = doc["service"]
    out.services["provider-control-middleware"] = SourceService(
        source=path, name="provider-control-middleware", protocol=svc["protocol"], host=svc["host"],
        port=svc["port"], carries_timeouts=False, carries_retries=False,
    )
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], paths=(route["path"],), methods=_methods(route["method"]),
            service_name="provider-control-middleware", upstream_protocol=svc["protocol"],
            upstream_host=svc["host"], upstream_port=svc["port"], required_scope=route["scope"],
            audience=doc["audience"], issuer=doc["issuer"], client_id=route["clientId"],
        )
    return out


def load_calling_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="calling-contract", issuer=_issuer_realm(doc["identity"]["issuer"]))
    out.declared_status = doc.get("status")
    svc = doc["service"]
    # The pinned contract carries timeouts; retries are owned by
    # scripts/render_kong_calling_routes.py (repository retry policy NONE).
    out.services[svc["name"]] = SourceService(**{**_service_from_contract(path, svc).__dict__, "retries": 0})
    common = doc["commonPolicy"]
    for route in doc["routes"]:
        out.routes[route["name"]] = SourceRoute(
            source=path, name=route["name"], hosts=(doc["host"],), paths=(route["path"],),
            methods=_methods(route["methods"]), protocols=_tuple(common["protocols"]),
            strip_path=common["stripPath"], preserve_host=common["preserveHost"], service_name=svc["name"],
            upstream_protocol=svc["protocol"], upstream_host=svc["host"], upstream_port=svc["port"],
            plugins=tuple(sorted(common["requiredPlugins"])), rate_per_minute=route["ratePerMinute"],
            max_body_bytes=_mb(common["requestBodyLimitMb"]), required_scope=route["requiredScope"],
            audience=doc["identity"]["audience"], issuer=out.issuer,
        )
    return out


def load_community_n8n_egress_contract(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="community-n8n-egress-contract", issuer=doc["identity"]["issuer"])
    out.declared_status = doc.get("status")
    svc = doc["service"]
    route = doc["route"]
    out.services[svc["name"]] = SourceService(
        source=path, name=svc["name"], protocol=svc["protocol"], host=f"${{{svc['host_source']}}}", port=svc["port"],
        carries_timeouts=False, carries_retries=False,
    )
    out.routes[svc["name"] + "-route"] = SourceRoute(
        source=path, name=svc["name"] + "-route", hosts=(route["host"],), paths=(route["path"],),
        methods=_methods(route["methods"]), protocols=_tuple(route["protocols"]), strip_path=route["strip_path"],
        service_name=svc["name"], upstream_protocol=svc["protocol"], upstream_host=f"${{{svc['host_source']}}}",
        upstream_port=svc["port"], plugins=tuple(sorted(doc["plugins"]["names"])),
        audience=doc["identity"]["audience"], issuer=doc["identity"]["issuer"],
    )
    return out


STANDBY_PLUGINS = ("ip-restriction", "rate-limiting", "request-size-limiting", "request-transformer")


def load_standby_design(path: str, doc: dict) -> SourceDocument:
    # Match, plugin and transport facts come from scripts/apply_kong_standby.py, the
    # only writer of these entities; standby.json carries the per-service policy.
    out = SourceDocument(path=path, format="standby-design", issuer=doc["issuer"])
    for svc in doc["services"]:
        out.services[svc["name"]] = SourceService(
            source=path, name=svc["name"], protocol="http", host="codestra-kong-standby-auth", port=8080,
            connect_timeout=svc["connectTimeoutMs"], read_timeout=svc["readTimeoutMs"],
            write_timeout=svc["writeTimeoutMs"], retries=svc["retries"],
        )
        out.routes[svc["name"] + "-route"] = SourceRoute(
            source=path, name=svc["name"] + "-route", hosts=(doc["stagingHostname"],), paths=(svc["path"],),
            methods=_methods(svc["methods"]), protocols=("http", "https"), strip_path=False, preserve_host=False,
            service_name=svc["name"], upstream_protocol="http", upstream_host="codestra-kong-standby-auth",
            upstream_port=8080, plugins=STANDBY_PLUGINS, rate_per_minute=svc["ratePerMinute"],
            max_body_bytes=svc["bodyLimitBytes"], required_scope=svc["requiredScope"], audience=doc["audience"],
            issuer=doc["issuer"],
        )
    return out


DESIGN_UPSTREAMS = "codestra-design-cell-upstreams"


def load_design_route_registry(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="design-route-registry")
    out.declared_status = doc.get("state")
    out.services[DESIGN_UPSTREAMS] = SourceService(
        source=path, name=DESIGN_UPSTREAMS, carries_timeouts=False, carries_retries=False,
    )
    for route in doc["routes"]:
        out.routes[route["id"]] = SourceRoute(
            source=path, name=route["id"], hosts=(route["host"],), paths=(route["path_prefix"],),
            methods=_methods(route["methods"]), service_name=DESIGN_UPSTREAMS, upstream_host=route["upstream"],
        )
    return out


def load_gateway_integration(path: str, doc: dict) -> SourceDocument:
    spec = doc["spec"]
    out = SourceDocument(path=path, format="gateway-integration", issuer=spec["authentication"]["issuer"])
    out.declared_environment = doc["metadata"]["environment"]
    up = spec["upstream"]
    out.services[up["service"]] = SourceService(
        source=path, name=up["service"], protocol=up["protocol"], host=up["dnsName"], port=up["port"],
        connect_timeout=up["timeouts"]["connectMs"], read_timeout=up["timeouts"]["readMs"],
        write_timeout=up["timeouts"]["writeMs"], retries=up["retries"],
    )
    policy = load_json(CURRENT_ROOT / "config/integrations/policies" / (spec["authentication"]["template"] + ".json"))
    for route in spec["routes"]:
        out.routes[doc["metadata"]["id"] + ":" + route["id"]] = SourceRoute(
            source=path, name=doc["metadata"]["id"] + ":" + route["id"], hosts=(spec["host"],),
            paths=(route["path"],), methods=_methods(route["methods"]), service_name=up["service"],
            upstream_protocol=up["protocol"], upstream_host=up["dnsName"], upstream_port=up["port"],
            plugins=tuple(sorted(policy["plugins"])), rate_per_minute=route["ratePerMinute"],
            max_body_bytes=route["maxBodyBytes"], audience=spec["authentication"]["audience"],
            issuer=spec["authentication"]["issuer"],
        )
    return out


def load_public_readonly_canary(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="public-readonly-canary")
    out.declared_status = doc.get("status")
    if any(route.get("kongRoute") is not None for route in doc["routes"]):
        raise FoundationError(f"{path}: canary paths must not declare Kong routes")
    out.edge_paths = tuple(route["path"] for route in doc["routes"])
    return out


def load_oidc_plugin_template(path: str, doc: dict) -> SourceDocument:
    out = SourceDocument(path=path, format="oidc-plugin-template")
    if doc.get("services") or doc.get("routes"):
        raise FoundationError(f"{path}: plugin template must not declare services or routes")
    out.global_plugins = tuple(p["name"] for p in doc.get("plugins", []) or [])
    for plugin in doc.get("plugins", []) or []:
        if plugin.get("name") == "openid-connect":
            out.issuer = _issuer_realm(plugin.get("config", {}).get("issuer"))
    return out


LOADERS = {
    "kong-declarative": (load_yaml, load_kong_declarative),
    "production-route-inventory": (load_json, load_production_inventory),
    "canonical-middleware-contract": (load_json, load_canonical_middleware_contract),
    "callback-contract": (load_json, load_callback_contract),
    "campaign-contract": (load_json, load_campaign_contract),
    "intake-contract": (load_json, load_intake_contract),
    "n8n-control-plane-contract": (load_json, load_n8n_control_plane_contract),
    "n8n-editor-contract": (load_json, load_n8n_editor_contract),
    "moneybee-contract": (load_json, load_moneybee_contract),
    "provider-control-contract": (load_json, load_provider_control_contract),
    "calling-contract": (load_json, load_calling_contract),
    "community-n8n-egress-contract": (load_json, load_community_n8n_egress_contract),
    "standby-design": (load_json, load_standby_design),
    "design-route-registry": (load_json, load_design_route_registry),
    "gateway-integration": (load_json, load_gateway_integration),
    "public-readonly-canary": (load_json, load_public_readonly_canary),
    "oidc-plugin-template": (load_yaml, load_oidc_plugin_template),
}


CURRENT_ROOT = ROOT


def load_sources(foundation: dict, root: Path = ROOT) -> dict[str, SourceDocument]:
    global CURRENT_ROOT
    CURRENT_ROOT = root
    documents: dict[str, SourceDocument] = {}
    for source in foundation["sources"]:
        path = root / source["path"]
        if not path.is_file():
            raise FoundationError(f"registered source does not exist: {source['path']}")
        if source["format"] not in LOADERS:
            raise FoundationError(f"{source['path']}: unknown source format {source['format']}")
        reader, loader = LOADERS[source["format"]]
        documents[source["path"]] = loader(source["path"], reader(path))
    return documents


# --------------------------------------------------------------------------- precedence


def is_regex_path(path: str) -> bool:
    return path.startswith("~")


def literal_prefix(path: str) -> str:
    """The longest literal prefix a Kong path can match: itself for prefix paths,
    the leading literal run for regex paths."""
    if not is_regex_path(path):
        return path
    body = path[1:]
    if body.startswith("^"):
        body = body[1:]
    match = re.match(r"[A-Za-z0-9/._-]*", body)
    return match.group(0) if match else ""


def route_priority(route: SourceRoute) -> tuple[int, int, int, int, int]:
    """Kong 3.x ``traditional_compatible`` router priority, highest wins.

    Bit layout (kong/router/transform.lua): match weight (number of matched
    criteria among methods/hosts/paths/headers/snis/sources/destinations),
    then plain hosts before wildcard hosts, then regex paths before prefix paths,
    then ``regex_priority``, then the longest prefix path. Headers, SNIs and
    L4 criteria are not used by any reviewed source, so they carry no weight here.
    """
    weight = sum(1 for values in (route.methods, route.hosts, route.paths) if values)
    hosts = route.hosts or ()
    plain_host = 1 if hosts and all("*" not in host for host in hosts) else 0
    paths = route.paths or ()
    regex = 1 if any(is_regex_path(p) for p in paths) else 0
    regex_priority = route.regex_priority if regex else 0
    max_len = max((len(p) for p in paths if not is_regex_path(p)), default=0)
    return (weight, plain_host, regex, regex_priority, max_len)


def _host_matches(pattern: str, host: str) -> bool:
    """Kong wildcard hosts: a leading or trailing ``*`` matches any label run."""
    if "*" not in pattern and "*" not in host:
        return pattern == host
    left, right = (pattern, host) if "*" in pattern else (host, pattern)
    if "*" in right:
        return left.replace("*", "") in right or right.replace("*", "") in left
    return re.fullmatch(re.escape(left).replace(re.escape("*"), ".+"), right) is not None


def _intersects(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> bool:
    if a is None or b is None:
        return True
    return any(_host_matches(left, right) for left in a for right in b)


def _methods_intersect(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> bool:
    if a is None or b is None:
        return True
    return bool(set(a) & set(b))


def regex_sample(path: str) -> str:
    """A representative concrete path admitted by a Kong regex path.

    Character classes become a single ``a`` (or ``n`` of them for exact
    quantifiers) and anchors are dropped. Used only to decide whether two regex
    paths, or a regex and a prefix path, can admit the same request.
    """
    body = path[1:]
    body = body[1:] if body.startswith("^") else body
    body = body[:-1] if body.endswith("$") else body
    body = re.sub(r"\[[^\]]*\]\{(\d+)\}", lambda m: "a" * int(m.group(1)), body)
    body = re.sub(r"\[[^\]]*\]\{\d*,\d*\}", "a", body)
    body = re.sub(r"\[[^\]]*\][+*?]?", "a", body)
    body = re.sub(r"\.[+*]", "a", body)
    return body.replace("\\", "")


def _regex_admits(path: str, candidate: str) -> bool:
    body = path[1:]
    body = body if body.startswith("^") else "^" + body
    try:
        return re.match(body, candidate) is not None
    except re.error:
        return True


def _pair_overlaps(left: str, right: str) -> bool:
    if is_regex_path(left) and is_regex_path(right):
        return _regex_admits(left, regex_sample(right)) or _regex_admits(right, regex_sample(left))
    if is_regex_path(left):
        return regex_sample(left).startswith(right) or right.startswith(literal_prefix(left))
    if is_regex_path(right):
        return regex_sample(right).startswith(left) or left.startswith(literal_prefix(right))
    return left.startswith(right) or right.startswith(left)


def _paths_overlap(a: tuple[str, ...] | None, b: tuple[str, ...] | None) -> bool:
    if a is None or b is None:
        return True
    return any(_pair_overlaps(left, right) for left in a for right in b)


def routes_overlap(a: SourceRoute, b: SourceRoute) -> bool:
    return _intersects(a.hosts, b.hosts) and _methods_intersect(a.methods, b.methods) and _paths_overlap(a.paths, b.paths)


@dataclass(frozen=True)
class Overlap:
    left: str
    right: str
    winner: str  # route id or "AMBIGUOUS"


def analyze_precedence(routes: dict[str, SourceRoute]) -> list[Overlap]:
    result: list[Overlap] = []
    ids = sorted(routes)
    for index, left_id in enumerate(ids):
        for right_id in ids[index + 1:]:
            left, right = routes[left_id], routes[right_id]
            if not routes_overlap(left, right):
                continue
            lp, rp = route_priority(left), route_priority(right)
            winner = left_id if lp > rp else right_id if rp > lp else "AMBIGUOUS"
            result.append(Overlap(left_id, right_id, winner))
    return result


# --------------------------------------------------------------------------- registry


def _index(items: Iterable[dict], key: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in items:
        if item[key] in out:
            raise FoundationError(f"duplicate {key}: {item[key]}")
        out[item[key]] = item
    return out


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise FoundationError(message)


def merge_route(desired: list[SourceRoute], observed: list[SourceRoute]) -> SourceRoute:
    """What the gateway would actually do: observed runtime facts win for match,
    transport, upstream and plugin set; desired contracts supply the policy values
    (rate, body, scope, audience) a readback never carries. A field one side
    leaves unspecified is taken from the other."""
    ordered = list(observed) + list(desired)
    values = dict(ordered[0].__dict__)
    for key in values:
        if key in ("source", "name", "regex_priority"):
            continue
        for candidate in ordered:
            value = getattr(candidate, key)
            if value is not None:
                values[key] = value
                break
    return SourceRoute(**values)


def materialize_route(entry: dict, documents: dict[str, SourceDocument]) -> tuple[SourceRoute, list[SourceRoute], list[SourceRoute]]:
    """Return (merged effective route, all desired, all observed) source routes for a registry entry."""
    desired: list[SourceRoute] = []
    observed: list[SourceRoute] = []
    for binding in entry["bindings"]:
        document = documents.get(binding["source"])
        _require(document is not None, f"route {entry['routeId']}: binding source not registered: {binding['source']}")
        route = document.routes.get(binding["route"])
        _require(route is not None, f"route {entry['routeId']}: {binding['source']} does not declare route {binding['route']}")
        (desired if binding["role"] == "DESIRED" else observed).append(route)
    _require(bool(desired or observed), f"route {entry['routeId']}: no bindings")
    return merge_route(desired, observed), desired, observed


def materialize_service(entry: dict, documents: dict[str, SourceDocument]) -> tuple[list[SourceService], list[SourceService]]:
    desired: list[SourceService] = []
    observed: list[SourceService] = []
    for binding in entry["bindings"]:
        document = documents.get(binding["source"])
        _require(document is not None, f"service {entry['serviceId']}: binding source not registered: {binding['source']}")
        service = document.services.get(binding["service"])
        _require(service is not None, f"service {entry['serviceId']}: {binding['source']} does not declare service {binding['service']}")
        (desired if binding["role"] == "DESIRED" else observed).append(service)
    return desired, observed


def _compare_specified(left: dict[str, Any], right: dict[str, Any]) -> list[tuple[str, Any, Any]]:
    diffs = []
    for key, value in left.items():
        other = right.get(key)
        if value is None or other is None:
            continue
        if isinstance(value, tuple) and isinstance(other, tuple):
            if sorted(value) != sorted(other):
                diffs.append((key, value, other))
        elif value != other:
            diffs.append((key, value, other))
    return diffs


# --------------------------------------------------------------------------- findings


def detect_route_findings(entry: dict, route: SourceRoute, service_entry: dict | None, foundation: dict) -> set[str]:
    rules = foundation["debtRules"]
    findings: set[str] = set()
    methods = set(route.methods or ())
    if route.hosts is None or not route.hosts:
        findings.add("HOST_UNSPECIFIED")
    else:
        if any("*" in host for host in route.hosts):
            findings.add("WILDCARD_HOST")
        if any(host in rules["legacyHosts"] for host in route.hosts):
            findings.add("LEGACY_HOST")
        if any(host.endswith(tuple(rules["placeholderHostSuffixes"])) for host in route.hosts):
            findings.add("PLACEHOLDER_HOST")
    if route.methods is None or not route.methods:
        findings.add("METHODS_UNSPECIFIED")
    elif len(methods & ALL_METHODS) >= 6:
        findings.add("ALL_METHODS")
    paths = route.paths or ()
    if not paths:
        findings.add("PATH_UNSPECIFIED")
    for path in paths:
        prefix = literal_prefix(path)
        if prefix in ("", "/") or path in ("/*", "~/.*", "~/"):
            findings.add("CATCH_ALL_PATH")
        elif prefix.rstrip("/") in rules["catchAllPrefixes"]:
            findings.add("CATCH_ALL_PREFIX")
        if any(segment in rules["adminPathSegments"] for segment in prefix.strip("/").split("/")):
            findings.add("ADMIN_PATH")
    if route.plugins is None:
        findings.add("PLUGIN_SET_UNSPECIFIED")
    else:
        plugins = set(route.plugins)
        if not plugins & AUTHENTICATION_PLUGINS:
            findings.add("NO_GATEWAY_AUTHENTICATION")
        if "key-auth" in plugins:
            findings.add("LEGACY_SHARED_KEY")
        if "cors" in plugins and "key-auth" in plugins:
            findings.add("CORS_WITH_SHARED_KEY")
        if methods & MUTATION_METHODS and "request-size-limiting" not in plugins and route.max_body_bytes is None:
            findings.add("UNBOUNDED_REQUEST_BODY")
        if "rate-limiting" not in plugins and route.rate_per_minute is None:
            findings.add("NO_RATE_LIMIT")
        if plugins & CLAIM_GUARD_PLUGINS and not plugins & {"jwt", "openid-connect"}:
            findings.add("CLAIM_GUARD_WITHOUT_TOKEN_AUTHENTICATION")
    if route.audience is not None and route.client_id is not None and route.audience == route.client_id:
        findings.add("AUDIENCE_IS_CLIENT_ID")
    host = route.upstream_host or ""
    if host.startswith("${"):
        findings.add("UPSTREAM_HOST_UNRESOLVED")
    if host and IPV4.fullmatch(host):
        findings.add("HARD_CODED_UPSTREAM_IP")
    if host and any(marker in host.lower() for marker in rules["providerUpstreamMarkers"]):
        findings.add("DIRECT_PROVIDER_UPSTREAM")
    if host in rules["legacyUpstreams"]:
        findings.add("LEGACY_UPSTREAM")
    if host in rules["testUpstreams"]:
        findings.add("TEST_UPSTREAM")
    if service_entry is not None:
        if service_entry["upstreamClass"] in rules["directApplicationUpstreamClasses"]:
            findings.add("DIRECT_APPLICATION_UPSTREAM")
    return findings


def detect_service_findings(entry: dict, desired: list[SourceService], observed: list[SourceService]) -> set[str]:
    findings: set[str] = set()
    for service in desired or observed:
        if service.carries_retries and service.retries is None:
            findings.add("IMPLICIT_RETRIES")
        if service.carries_timeouts and None in (service.connect_timeout, service.read_timeout, service.write_timeout):
            findings.add("IMPLICIT_TIMEOUTS")
        if service.carries_timeouts and (service.connect_timeout, service.read_timeout, service.write_timeout) == (
            KONG_DEFAULT_TIMEOUT_MS, KONG_DEFAULT_TIMEOUT_MS, KONG_DEFAULT_TIMEOUT_MS
        ):
            findings.add("KONG_DEFAULT_TIMEOUTS")
        if not service.carries_retries:
            findings.add("RETRIES_UNDECLARED" if desired else "RETRIES_UNRECORDED")
        if not service.carries_timeouts:
            findings.add("TIMEOUTS_UNDECLARED")
    return findings


# --------------------------------------------------------------------------- validation


def validate_registry_shape(foundation: dict) -> None:
    _require(foundation["schema"] == SCHEMA, "foundation schema mismatch")
    _require(foundation["runtimeApplyAuthorized"] is False, "foundation must remain source-only")
    _require(foundation["status"] == "SOURCE_CANDIDATE_NO_RUNTIME_APPLY", "foundation status must remain a source candidate")
    _require(set(foundation["environments"]) == {"development", "staging", "production"},
             "development, staging, and production must be explicit")
    rules = foundation["boundaryRules"]
    for key, expected in (
        ("edgeAuthority", "caddy"), ("identityAuthority", "keycloak"),
        ("businessAuthorizationAuthority", "middleware"), ("directProviderRoutesAllowed", False),
        ("fallbackRoutesAllowed", False), ("adminPubliclyReachable", False),
        ("unknownVersionBehavior", "controlled-rejection"), ("wildcardRoutesAllowed", False),
        ("corsCredentialsWithWildcardOriginAllowed", False), ("clientSuppliedIdentityHeadersTrusted", False),
    ):
        _require(rules.get(key) == expected, f"boundaryRules.{key} must be {expected!r}")
    for name in ("timeout", "retry", "rateLimit", "requestSize"):
        _require(isinstance(foundation["profiles"].get(name), dict) and foundation["profiles"][name], f"profiles.{name} missing")
    for name, profile in foundation["profiles"]["timeout"].items():
        for key in ("connectMs", "readMs", "writeMs"):
            _require(isinstance(profile.get(key), int) and profile[key] > 0, f"timeout profile {name}.{key} must be a positive integer")
            _require(profile[key] <= foundation["profiles"]["limits"]["maxTimeoutMs"], f"timeout profile {name}.{key} exceeds the maximum")
    for name, profile in foundation["profiles"]["retry"].items():
        _require(isinstance(profile.get("retries"), int) and 0 <= profile["retries"] <= foundation["profiles"]["limits"]["maxRetries"],
                 f"retry profile {name} must declare bounded retries")
    for name, profile in foundation["profiles"]["rateLimit"].items():
        _require(profile.get("perMinute") is None or (isinstance(profile["perMinute"], int) and profile["perMinute"] > 0),
                 f"rate-limit profile {name}.perMinute must be a positive integer or null")
    for name, profile in foundation["profiles"]["requestSize"].items():
        _require(profile.get("maxBodyBytes") is None or (isinstance(profile["maxBodyBytes"], int) and profile["maxBodyBytes"] > 0),
                 f"request-size profile {name}.maxBodyBytes must be a positive integer or null")
    _require(set(foundation["authenticationClasses"]) == {"PUBLIC", "AUTHENTICATED", "SERVICE_AUTHENTICATED", "ADMIN_INTERNAL", "INTERNAL"},
             "authentication classes must be exactly the five gateway classes")


def validate_source_discovery(foundation: dict, root: Path = ROOT) -> None:
    """Every file that looks like a Kong route/plugin source must be registered or
    excluded with a reason, so a new contract cannot arrive undocumented."""
    discovery = foundation["sourceDiscovery"]
    registered = {source["path"] for source in foundation["sources"]}
    excluded = {item["path"]: item["reason"] for item in discovery["excluded"]}
    for path, reason in excluded.items():
        _require(bool(reason), f"sourceDiscovery exclusion {path} needs a reason")
        _require(path not in registered, f"sourceDiscovery exclusion {path} is also a registered source")
    found: set[str] = set()
    for pattern in discovery["patterns"]:
        for match in sorted(root.glob(pattern)):
            if match.is_file():
                found.add(match.relative_to(root).as_posix())
    unregistered = sorted(found - registered - set(excluded))
    _require(not unregistered, f"unregistered Kong source files (register them in sources[] or exclude with a reason): {unregistered}")
    stale = sorted(set(excluded) - found)
    _require(not stale, f"sourceDiscovery exclusions for files that no longer exist: {stale}")


def validate_sources(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    for source in foundation["sources"]:
        for key in ("path", "format", "environment", "role", "activation"):
            _require(key in source, f"source {source.get('path')} lacks {key}")
        _require(source["environment"] in set(foundation["environments"]) | {"none"}, f"source {source['path']} has unknown environment")
        _require(source["role"] in foundation["enums"]["sourceRoles"], f"source {source['path']} has unknown role {source['role']}")
        _require(source["activation"] in foundation["enums"]["activations"], f"source {source['path']} has unknown activation")
        document = documents[source["path"]]
        environment = foundation["environments"].get(source["environment"], {})
        if document.issuer and source["environment"] in ("staging", "production"):
            _require(document.issuer == environment["issuer"],
                     f"source {source['path']} binds issuer {document.issuer} but {source['environment']} requires {environment['issuer']}")
        if document.declared_environment is not None:
            _require(document.declared_environment == source["environment"],
                     f"source {source['path']} declares environment {document.declared_environment} but is registered as {source['environment']}")
        if source["role"] in ("DEPLOYED_CANDIDATE", "RUNTIME_READBACK", "CONTRACT", "OVERLAY"):
            pass
        if document.global_plugins and source["role"] != "PLUGIN_TEMPLATE":
            for plugin in document.global_plugins:
                _require(plugin in foundation["pluginGovernance"]["globalPluginsAllowed"],
                         f"source {source['path']} declares global plugin {plugin} which is not allowed globally")
                _require(plugin not in AUTHENTICATION_PLUGINS, f"authentication plugin {plugin} must never be global")
        if source["role"] == "PLUGIN_TEMPLATE":
            _require(source["activation"] == "TEMPLATE_NOT_LOADABLE", f"plugin template {source['path']} must be TEMPLATE_NOT_LOADABLE")


def validate_no_undocumented_routes(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    bound: dict[str, set[str]] = {path: set() for path in documents}
    for entry in foundation["routes"]:
        for binding in entry["bindings"]:
            bound[binding["source"]].add(binding["route"])
    for path, document in documents.items():
        missing = sorted(set(document.routes) - bound[path])
        _require(not missing, f"undocumented routes in {path}: {missing}")
    bound_services: dict[str, set[str]] = {path: set() for path in documents}
    for entry in foundation["services"]:
        for binding in entry["bindings"]:
            bound_services[binding["source"]].add(binding["service"])
    for path, document in documents.items():
        missing = sorted(set(document.services) - bound_services[path])
        _require(not missing, f"undocumented services in {path}: {missing}")


def validate_services(foundation: dict, documents: dict[str, SourceDocument]) -> dict[str, dict]:
    services = _index(foundation["services"], "serviceId")
    enums = foundation["enums"]
    profiles = foundation["profiles"]
    drift = {(d["subject"], d["field"]): d for d in foundation["knownDrift"]}
    seen_drift: set[tuple[str, str]] = set()
    for entry in services.values():
        for key in ("owner", "environment", "purpose", "trafficClass", "upstreamClass", "upstream", "healthProfile",
                    "timeoutProfile", "retryProfile", "authenticationProfile", "authorizationPrerequisiteProfile",
                    "rateLimitProfile", "requestSizeProfile", "observabilityProfile", "lifecycle", "disposition",
                    "acceptedFindings", "bindings"):
            _require(key in entry, f"service {entry['serviceId']} lacks {key}")
        _require(entry["environment"] in foundation["environments"], f"service {entry['serviceId']} has unknown environment")
        _require(entry["trafficClass"] in enums["trafficClasses"], f"service {entry['serviceId']} has unknown traffic class")
        _require(entry["upstreamClass"] in enums["upstreamClasses"], f"service {entry['serviceId']} has unknown upstream class")
        _require(entry["lifecycle"] in enums["lifecycles"], f"service {entry['serviceId']} has unknown lifecycle")
        _require(entry["disposition"] in enums["dispositions"], f"service {entry['serviceId']} has unknown disposition")
        _require(entry["timeoutProfile"] in profiles["timeout"], f"service {entry['serviceId']} uses unknown timeout profile")
        _require(entry["retryProfile"] in profiles["retry"], f"service {entry['serviceId']} uses unknown retry profile")
        _require(entry["healthProfile"] in profiles["health"], f"service {entry['serviceId']} uses unknown health profile")
        _require(entry["authenticationProfile"] in foundation["authenticationClasses"], f"service {entry['serviceId']} has unknown authentication profile")
        _require(entry["observabilityProfile"] in profiles["observability"], f"service {entry['serviceId']} uses unknown observability profile")
        _require(entry["rateLimitProfile"] in profiles["rateLimit"], f"service {entry['serviceId']} uses unknown rate-limit profile")
        _require(entry["requestSizeProfile"] in profiles["requestSize"], f"service {entry['serviceId']} uses unknown request-size profile")
        _require(entry["authorizationPrerequisiteProfile"] in enums["authorizationPrerequisiteProfiles"],
                 f"service {entry['serviceId']} has unknown authorization prerequisite profile")
        if entry["upstreamClass"] in foundation["debtRules"]["directApplicationUpstreamClasses"]:
            _require(bool(entry.get("directUpstreamReason")), f"direct application service {entry['serviceId']} requires directUpstreamReason")
        if entry["upstreamClass"] in foundation["debtRules"]["middlewareUpstreamClasses"]:
            aliases = {(a["host"], a["port"]) for a in foundation["boundaryRules"]["middlewareUpstreamAliases"]}
            _require((entry["upstream"]["host"], entry["upstream"]["port"]) in aliases,
                     f"service {entry['serviceId']} targets an undeclared Middleware alias {entry['upstream']['host']}:{entry['upstream']['port']}")
        desired, observed = materialize_service(entry, documents)
        _require(bool(desired or observed), f"service {entry['serviceId']} has no bindings")
        expected_upstream = entry["upstream"]
        for service in desired:
            for key, registry_key in (("protocol", "protocol"), ("host", "host"), ("port", "port")):
                value = getattr(service, key)
                if value is not None:
                    _require(value == expected_upstream[registry_key],
                             f"service {entry['serviceId']}: {service.source} declares {key}={value!r} but registry says {expected_upstream[registry_key]!r}")
        timeout = profiles["timeout"][entry["timeoutProfile"]]
        retry = profiles["retry"][entry["retryProfile"]]
        for service in desired:
            if service.carries_timeouts and service.connect_timeout is not None:
                actual = (service.connect_timeout, service.read_timeout, service.write_timeout)
                expected = (timeout["connectMs"], timeout["readMs"], timeout["writeMs"])
                _require(actual == expected, f"service {entry['serviceId']}: {service.source} timeouts {actual} do not match profile {entry['timeoutProfile']} {expected}")
            if service.carries_retries and service.retries is not None:
                _require(service.retries == retry["retries"], f"service {entry['serviceId']}: {service.source} retries={service.retries} do not match profile {entry['retryProfile']}")
        if desired and desired[0].carries_retries and desired[0].retries is None:
            _require(retry["retries"] == KONG_DEFAULT_RETRIES, f"service {entry['serviceId']} leaves retries implicit; retry profile must be the Kong default profile")
        for service in observed:
            reference = desired[0] if desired else None
            if reference is None:
                continue
            for key, observed_value, desired_value in _compare_specified(service.field_values(), reference.field_values()):
                if key == "retries" and not service.carries_retries:
                    continue
                subject = (entry["serviceId"], key)
                declared = drift.get(subject)
                _require(declared is not None,
                         f"service {entry['serviceId']}: undeclared runtime drift on {key}: observed {observed_value!r} desired {desired_value!r}")
                _require(declared["observed"] == _plain(observed_value) and declared["desired"] == _plain(desired_value),
                         f"service {entry['serviceId']}: knownDrift for {key} is stale")
                seen_drift.add(subject)
        findings = detect_service_findings(entry, desired, observed)
        accepted = set(entry["acceptedFindings"])
        _require(findings == accepted,
                 f"service {entry['serviceId']}: detected findings {sorted(findings)} != accepted {sorted(accepted)}")
        if entry["lifecycle"] == "CANONICAL":
            forbidden = accepted & set(foundation["debtRules"]["forbiddenOnCanonical"])
            _require(not forbidden, f"canonical service {entry['serviceId']} carries forbidden findings {sorted(forbidden)}")
        if entry["lifecycle"] == "CANONICAL" and retry["retries"] > 0:
            _require(retry.get("transportSafe") is True, f"canonical service {entry['serviceId']} uses retry profile {entry['retryProfile']} which is not marked transport safe")
        if entry["lifecycle"] == "DESIGN_ONLY":
            continue
    stale = {(d["subject"], d["field"]) for d in foundation["knownDrift"] if d["kind"] == "service"} - seen_drift
    _require(not stale, f"stale knownDrift entries: {sorted(stale)}")
    return services


def _plain(value: Any) -> Any:
    if isinstance(value, tuple):
        return sorted(value)
    return value


def validate_routes(foundation: dict, documents: dict[str, SourceDocument], services: dict[str, dict]) -> dict[str, SourceRoute]:
    routes = _index(foundation["routes"], "routeId")
    enums = foundation["enums"]
    profiles = foundation["profiles"]
    rules = foundation["debtRules"]
    drift = {(d["subject"], d["field"]): d for d in foundation["knownDrift"] if d["kind"] == "route"}
    seen_drift: set[tuple[str, str]] = set()
    materialized: dict[str, SourceRoute] = {}
    for entry in routes.values():
        route_id = entry["routeId"]
        for key in ("serviceId", "environment", "bindings", "trafficClass", "authentication", "mechanism",
                    "rateLimitProfile", "requestSizeProfile", "lifecycle", "activation", "disposition",
                    "acceptedFindings"):
            _require(key in entry, f"route {route_id} lacks {key}")
        _require(entry["serviceId"] in services, f"route {route_id} references unknown service {entry['serviceId']}")
        service_entry = services[entry["serviceId"]]
        _require(entry["environment"] in foundation["environments"], f"route {route_id} has unknown environment")
        _require(entry["environment"] == service_entry["environment"], f"route {route_id} environment differs from its service")
        _require(entry["trafficClass"] in enums["trafficClasses"], f"route {route_id} has unknown traffic class")
        _require(entry["authentication"] in foundation["authenticationClasses"], f"route {route_id} has unknown authentication class")
        _require(entry["mechanism"] in enums["mechanisms"], f"route {route_id} has unknown mechanism {entry['mechanism']}")
        _require(entry["lifecycle"] in enums["lifecycles"], f"route {route_id} has unknown lifecycle")
        _require(entry["activation"] in enums["activations"], f"route {route_id} has unknown activation")
        _require(entry["disposition"] in enums["dispositions"], f"route {route_id} has unknown disposition")
        _require(entry["rateLimitProfile"] in profiles["rateLimit"], f"route {route_id} uses unknown rate-limit profile")
        _require(entry["requestSizeProfile"] in profiles["requestSize"], f"route {route_id} uses unknown request-size profile")
        primary, desired, observed = materialize_route(entry, documents)
        for binding in entry["bindings"]:
            source = next(s for s in foundation["sources"] if s["path"] == binding["source"])
            _require(source["environment"] == entry["environment"],
                     f"route {route_id}: binding {binding['source']} is a {source['environment']} source but the route is {entry['environment']}")
        for other in desired[1:]:
            diffs = _compare_specified(desired[0].field_values(), other.field_values())
            _require(not diffs, f"route {route_id}: desired sources disagree {desired[0].source} vs {other.source}: {diffs}")
        for obs in observed:
            reference = desired[0] if desired else None
            if reference is None:
                continue
            for key, observed_value, desired_value in _compare_specified(obs.field_values(), reference.field_values()):
                subject = (route_id, key)
                declared = drift.get(subject)
                _require(declared is not None,
                         f"route {route_id}: undeclared runtime drift on {key}: observed {_plain(observed_value)!r} desired {_plain(desired_value)!r}")
                _require(declared["observed"] == _plain(observed_value) and declared["desired"] == _plain(desired_value),
                         f"route {route_id}: knownDrift for {key} is stale")
                seen_drift.add(subject)
        materialized[route_id] = primary
        for binding_route in desired + observed:
            if binding_route.service_name is not None:
                _require(any(b["service"] == binding_route.service_name and b["source"] == binding_route.source for b in service_entry["bindings"]),
                         f"route {route_id}: {binding_route.source} binds service {binding_route.service_name} which is not a binding of {entry['serviceId']}")
        # profile cross-checks
        rate = profiles["rateLimit"][entry["rateLimitProfile"]]
        if primary.rate_per_minute is not None:
            _require(rate["perMinute"] == primary.rate_per_minute,
                     f"route {route_id}: source rate {primary.rate_per_minute}/min does not match profile {entry['rateLimitProfile']}")
        size = profiles["requestSize"][entry["requestSizeProfile"]]
        if primary.max_body_bytes is not None:
            _require(size["maxBodyBytes"] == primary.max_body_bytes,
                     f"route {route_id}: source body limit {primary.max_body_bytes} does not match profile {entry['requestSizeProfile']}")
        if primary.required_scope is not None:
            _require(primary.required_scope in entry.get("requiredScopes", []),
                     f"route {route_id}: source scope {primary.required_scope} is not registered")
        if primary.audience is not None:
            _require(entry.get("audience") == primary.audience,
                     f"route {route_id}: source audience {primary.audience} != registered {entry.get('audience')}")
        # wildcard / explicit posture
        for values, label in ((primary.hosts, "hosts"), (primary.paths, "paths"), (primary.methods, "methods")):
            for value in values or ():
                _require(value not in ("*", "/*"), f"route {route_id}: wildcard {label} are forbidden")
        # findings
        findings = detect_route_findings(entry, primary, service_entry, foundation)
        accepted = set(entry["acceptedFindings"])
        _require(findings == accepted, f"route {route_id}: detected findings {sorted(findings)} != accepted {sorted(accepted)}")
        # classification rules
        methods = set(primary.methods or ())
        if entry["authentication"] == "PUBLIC":
            _require(bool(entry.get("publicReason")), f"public route {route_id} requires publicReason")
            if methods & MUTATION_METHODS:
                _require(entry["lifecycle"] in rules["publicMutationLifecycles"] or entry["activation"] == "BLOCKED",
                         f"public mutation route {route_id} must be legacy or blocked")
        not_activatable = entry["activation"] in rules["nonActivatableActivations"]
        if "NO_GATEWAY_AUTHENTICATION" in findings:
            _require(entry["mechanism"] == "NONE", f"route {route_id} has no authentication plugin but claims mechanism {entry['mechanism']}")
            _require(entry["authentication"] == "PUBLIC" or entry["activation"] == "BLOCKED"
                     or (not_activatable and bool(entry.get("authenticationGap"))),
                     f"route {route_id} has no gateway authentication and is neither PUBLIC, BLOCKED nor a design with a declared authenticationGap")
        if entry["mechanism"] == "NONE":
            _require("NO_GATEWAY_AUTHENTICATION" in findings or "PLUGIN_SET_UNSPECIFIED" in findings,
                     f"route {route_id} claims mechanism NONE but an authentication plugin is present")
        if entry["mechanism"] == "KEY_AUTH_SHARED":
            _require(entry["lifecycle"] in rules["sharedKeyLifecycles"], f"shared-key route {route_id} must be legacy")
            _require("LEGACY_SHARED_KEY" in findings, f"route {route_id} claims KEY_AUTH_SHARED without key-auth")
        if entry["authentication"] in ("AUTHENTICATED", "SERVICE_AUTHENTICATED", "ADMIN_INTERNAL", "INTERNAL"):
            # The class states the required posture; a NONE mechanism records the
            # observed gap and is tolerated only while the route cannot be activated.
            _require(entry["mechanism"] != "NONE" or entry["activation"] == "BLOCKED"
                     or (not_activatable and bool(entry.get("authenticationGap"))),
                     f"route {route_id} is {entry['authentication']} without a mechanism and is not blocked")
            if entry["mechanism"] in rules["tokenMechanisms"]:
                _require(bool(entry.get("audience")), f"token-authenticated route {route_id} requires an audience")
        if entry["authentication"] == "ADMIN_INTERNAL" and entry["activation"] != "BLOCKED":
            _require(entry["mechanism"] != "NONE" and entry.get("requiredScopes"), f"admin route {route_id} requires a mechanism and scopes")
        if "ADMIN_PATH" in findings:
            _require(entry["authentication"] == "ADMIN_INTERNAL" or entry["activation"] == "BLOCKED",
                     f"route {route_id} exposes an administrative path without ADMIN_INTERNAL classification")
        if "PLACEHOLDER_HOST" in findings:
            _require(entry["activation"] != "RUNTIME_OBSERVED", f"route {route_id} runs on a placeholder host")
        if "DIRECT_PROVIDER_UPSTREAM" in findings or "HARD_CODED_UPSTREAM_IP" in findings:
            _require(entry["activation"] == "BLOCKED", f"route {route_id} targets a provider or hard-coded IP upstream and is not blocked")
        for path in primary.paths or ():
            _require(path not in foundation["edgeOwnedPaths"] or not (set(primary.hosts or ()) & set(foundation["edgeOwnedHosts"])),
                     f"route {route_id} declares an edge-owned path {path}")
        if entry["lifecycle"] == "CANONICAL":
            forbidden = accepted & set(rules["forbiddenOnCanonical"])
            _require(not forbidden, f"canonical route {route_id} carries forbidden findings {sorted(forbidden)}")
            _require(entry["activation"] in ("RUNTIME_OBSERVED", "SOURCE_CANDIDATE"), f"canonical route {route_id} has activation {entry['activation']}")
            _require(bool(desired), f"canonical route {route_id} must have a DESIRED binding")
        if entry["activation"] == "RUNTIME_OBSERVED":
            _require(bool(observed), f"route {route_id} claims RUNTIME_OBSERVED without an OBSERVED binding")
        if observed and entry["activation"] not in ("RUNTIME_OBSERVED", "BLOCKED"):
            raise FoundationError(f"route {route_id} has an OBSERVED binding but activation {entry['activation']}")
        if entry["activation"] == "BLOCKED":
            _require(bool(entry.get("blockedReason")), f"blocked route {route_id} requires blockedReason")
        if entry["lifecycle"] in ("DESIGN_ONLY", "PREPARED_DISABLED", "PROPOSED"):
            _require(entry["activation"] in ("DESIGN_ONLY", "PREPARED_DISABLED", "PROPOSED"),
                     f"route {route_id} lifecycle {entry['lifecycle']} cannot have activation {entry['activation']}")
        if entry["lifecycle"] == "LEGACY":
            _require(bool(entry.get("retirement")), f"legacy route {route_id} requires a retirement statement")
        if entry.get("supersededBy"):
            _require(entry["supersededBy"] in routes, f"route {route_id} supersededBy unknown route {entry['supersededBy']}")
            _require(entry["lifecycle"] in ("LEGACY", "TRANSITIONAL"), f"superseded route {route_id} must be legacy or transitional")
        if entry.get("legacyRetirement"):
            pass
    stale = set(drift) - seen_drift
    _require(not stale, f"stale route knownDrift entries: {sorted(stale)}")
    return materialized


def validate_precedence(foundation: dict, routes: dict[str, dict], materialized: dict[str, SourceRoute]) -> list[Overlap]:
    universes: dict[str, dict[str, SourceRoute]] = {}
    for route_id, route in materialized.items():
        entry = routes[route_id]
        if entry["activation"] not in foundation["precedence"]["analyzedActivations"]:
            continue
        universes.setdefault(entry["environment"], {})[route_id] = route
    declared = {(c["left"], c["right"]): c for c in foundation["precedence"]["knownConflicts"]}
    seen: set[tuple[str, str]] = set()
    overlaps: list[Overlap] = []
    for environment, universe in universes.items():
        for overlap in analyze_precedence(universe):
            key = (overlap.left, overlap.right)
            conflict = declared.get(key)
            _require(conflict is not None,
                     f"undeclared route overlap in {environment}: {overlap.left} vs {overlap.right} (winner {overlap.winner})")
            _require(conflict["winner"] == overlap.winner,
                     f"conflict {overlap.left} vs {overlap.right}: registry expects winner {conflict['winner']} but router yields {overlap.winner}")
            _require(conflict["resolution"] in foundation["enums"]["conflictResolutions"],
                     f"conflict {overlap.left} vs {overlap.right} has unknown resolution")
            if overlap.winner == "AMBIGUOUS":
                _require(conflict["resolution"] != "DETERMINISTIC_SPECIFICITY", "ambiguous overlaps cannot be resolved by specificity")
                for route_id in key:
                    _require(routes[route_id]["lifecycle"] != "CANONICAL" or routes[route_id]["activation"] == "SOURCE_CANDIDATE",
                             f"canonical runtime route {route_id} is in an ambiguous overlap")
            else:
                loser = overlap.right if overlap.winner == overlap.left else overlap.left
                if routes[loser]["lifecycle"] == "CANONICAL" and routes[overlap.winner]["lifecycle"] in ("LEGACY", "TRANSITIONAL"):
                    _require(conflict["resolution"] == "LEGACY_SHADOWS_SUCCESSOR_UNTIL_RETIRED",
                             f"canonical route {loser} is shadowed by {overlap.winner}; resolution must acknowledge it")
            seen.add(key)
            overlaps.append(overlap)
    stale = set(declared) - seen
    _require(not stale, f"stale knownConflicts: {sorted(stale)}")
    return overlaps


def validate_plugins(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    registry = _index(foundation["plugins"], "plugin")
    governance = foundation["pluginGovernance"]
    for name, entry in registry.items():
        for key in governance["requiredMetadata"]:
            _require(key in entry and entry[key] not in (None, "", []), f"plugin {name} lacks {key}")
        _require(set(entry["allowedScopes"]) <= set(governance["scopeValues"]), f"plugin {name} has unknown scopes")
        if entry["authentication"]:
            _require("GLOBAL" not in entry["allowedScopes"], f"authentication plugin {name} must not allow GLOBAL scope")
            _require(name in AUTHENTICATION_PLUGINS, f"plugin {name} is marked authentication but is not an authentication plugin")
        if "GLOBAL" in entry["allowedScopes"]:
            _require(name in governance["globalPluginsAllowed"], f"plugin {name} allows GLOBAL scope but is not in the global allowlist")
    for plugin in governance["globalPluginsAllowed"]:
        _require(plugin in registry and "GLOBAL" in registry[plugin]["allowedScopes"], f"global allowlist entry {plugin} is not registered with GLOBAL scope")
    used: dict[str, set[str]] = {}
    for path, document in documents.items():
        for plugin in document.global_plugins:
            used.setdefault(plugin, set()).add(path)
        for route in document.routes.values():
            for plugin in route.plugins or ():
                used.setdefault(plugin, set()).add(path)
        for service in document.services.values():
            for plugin in service.plugins:
                used.setdefault(plugin, set()).add(path)
    for plugin, paths in used.items():
        _require(plugin in registry, f"plugin {plugin} used by {sorted(paths)} is not governed")
        for path in paths:
            _require(path in registry[plugin]["configurationSources"],
                     f"plugin {plugin}: {path} uses it but is not a registered configuration source")
    for name, entry in registry.items():
        for path in entry["configurationSources"]:
            _require(path in used.get(name, set()) or (CURRENT_ROOT / path).is_file(),
                     f"plugin {name}: configuration source {path} does not exist")
    priorities = {name: entry["priority"] for name, entry in registry.items()}
    readback = {s["path"] for s in foundation["sources"] if s["role"] == "RUNTIME_READBACK"}
    for path, document in documents.items():
        if path in readback:
            continue  # observed plugin phases are reconciled through knownDrift
        for route in document.routes.values():
            plugins = set(route.plugins or ())
            guards = plugins & CLAIM_GUARD_PLUGINS
            auth = plugins & {"jwt", "openid-connect"}
            for guard in guards:
                _require(all(priorities[a] > priorities[guard] for a in auth) if auth else True,
                         f"{path}:{route.name}: claim guard {guard} would run before its authentication plugin")
            if "pre-function" in plugins:
                _require(path in governance["preFunctionAllowedSources"],
                         f"{path}:{route.name}: pre-function is only allowed for raw-metadata guards in {governance['preFunctionAllowedSources']}")


def validate_environments(foundation: dict, documents: dict[str, SourceDocument]) -> None:
    environments = foundation["environments"]
    _require(environments["staging"]["issuer"] != environments["production"]["issuer"], "staging and production must not share an issuer")
    _require(environments["development"]["issuer"] is None, "development must not bind a shared issuer")
    for overlay in foundation["environments"]["staging"]["overlays"]:
        base = documents[overlay["base"]]
        over = documents[overlay["overlay"]]
        _require(set(over.routes) <= set(base.routes), f"overlay {overlay['overlay']} declares routes absent from {overlay['base']}")
        excluded = set(base.routes) - set(over.routes)
        _require(excluded == set(overlay["excludedRoutes"]),
                 f"overlay {overlay['overlay']} excludes {sorted(excluded)} but registry says {sorted(overlay['excludedRoutes'])}")
        for name, route in over.routes.items():
            diffs = [d for d in _compare_specified(route.field_values(), base.routes[name].field_values()) if d[0] not in ("audience",)]
            _require(not diffs, f"overlay {overlay['overlay']} route {name} drifts from base: {diffs}")
        _require(over.issuer == environments["staging"]["issuer"], f"overlay {overlay['overlay']} must use the staging issuer")
        _require(base.issuer == environments["production"]["issuer"], f"base {overlay['base']} must use the production issuer")
        for name, service in over.services.items():
            base_service = base.services.get(name)
            _require(base_service is not None, f"overlay {overlay['overlay']} service {name} has no base service")
            if (service.host, service.port) == (base_service.host, base_service.port):
                _require(overlay.get("sharedUpstreamAliases") is True,
                         f"overlay {overlay['overlay']} reuses production upstream alias {service.host}:{service.port} without declaring sharedUpstreamAliases")


def validate_node(foundation: dict, root: Path = ROOT) -> None:
    node = foundation["node"]
    compose = load_yaml(root / node["compose"])
    gateway = compose["services"][node["composeService"]]
    environment = gateway["environment"]
    _require(environment.get("KONG_ADMIN_LISTEN") == "127.0.0.1:8001", "Admin API must remain container-loopback only")
    _require(environment.get("KONG_ADMIN_GUI_LISTEN") == "off", "Kong Manager must remain off")
    ports = [str(p) for p in gateway.get("ports", [])]
    _require(all(p.startswith("127.0.0.1:") for p in ports), "every published port must bind host loopback")
    _require(not any(":8001" in p or ":8100" in p or ":8002" in p for p in ports), "Admin, Manager and Status must not be published")
    _require(environment.get("KONG_PG_SSL") == "on" and environment.get("KONG_PG_SSL_VERIFY") == "on", "database TLS verification must be enabled")
    _require("@${KONG_IMAGE_DIGEST:?" in gateway.get("image", ""), "gateway image must use an immutable digest")
    _require(str(environment.get("KONG_TRUSTED_IPS", "")).startswith("${KONG_TRUSTED_IPS:?"), "trusted_ips must be required from the deployment with no default")
    _require(environment.get("KONG_REAL_IP_HEADER") == "X-Forwarded-For" and environment.get("KONG_REAL_IP_RECURSIVE") == "on",
             "forwarded client address must be taken from X-Forwarded-For recursively")
    _require(environment.get("KONG_UNTRUSTED_LUA") == "sandbox", "untrusted_lua must stay sandboxed")
    _require(environment.get("KONG_UNTRUSTED_LUA_SANDBOX_REQUIRES") == "cjson.safe", "sandbox requires must be exactly cjson.safe")
    _require(environment.get("KONG_VAULTS") == "env", "env vault must be enabled")
    _require(environment.get("KONG_HEADERS") == "off", "server headers must be off")
    _require(environment.get("KONG_STATUS_LISTEN") == "0.0.0.0:8100", "status listener must be the private 8100 listener")
    _require(environment.get("KONG_ADMIN_ACCESS_LOG") == "off" and environment.get("KONG_STATUS_ACCESS_LOG") == "off", "admin/status access logs stay off")
    _require(environment.get("KONG_PROXY_ACCESS_LOG") == "/dev/stdout" and environment.get("KONG_PROXY_ERROR_LOG") == "/dev/stderr", "proxy logs go to the container streams")
    _require(gateway.get("read_only") is True, "container root must be read-only")
    _require(gateway.get("cap_drop") == ["ALL"], "all capabilities must be dropped")
    _require("no-new-privileges:true" in gateway.get("security_opt", []), "no-new-privileges is required")
    _require("healthcheck" in gateway, "a health check is required")
    _require("docker.sock" not in json.dumps(gateway), "the Docker socket must never be mounted")
    _require(not gateway.get("privileged") and not gateway.get("network_mode"), "privileged and host networking are forbidden")
    for secret in ("kong_license", "kong_database_runtime_password"):
        _require(secret in gateway.get("secrets", []), f"secret {secret} must be mounted as a file")
    for name, definition in compose.get("secrets", {}).items():
        _require(set(definition) == {"file"} and definition["file"].startswith("/etc/codestra/secrets/"), f"secret {name} must be a root-owned host file path")
    for network in compose.get("networks", {}).values():
        _require(network.get("external") is True, "every network must be an existing external network")
    conf = (root / node["confExample"]).read_text(encoding="utf-8")
    settings = dict(re.findall(r"^([a-z_]+)\s*=\s*(\S+)", conf, flags=re.MULTILINE))
    for key, expected in node["confMustEqual"].items():
        _require(settings.get(key) == expected, f"kong.conf.example {key} must be {expected!r} (found {settings.get(key)!r})")
    # env template completeness
    declared = set(re.findall(r"^([A-Z0-9_]+)=", (root / node["runtimeEnvExample"]).read_text(encoding="utf-8"), flags=re.MULTILINE))
    for candidate in node["vaultReferenceSources"]:
        text = (root / candidate).read_text(encoding="utf-8")
        for reference in set(VAULT_ENV.findall(text)):
            variable = reference.upper().replace("-", "_")
            _require(variable in declared, f"{candidate} references {{vault://env/{reference}}} but {node['runtimeEnvExample']} does not declare {variable}")
    observability = dict(re.findall(r"^([A-Z_]+)=(\S+)", (root / node["observabilityEnvExample"]).read_text(encoding="utf-8"), flags=re.MULTILINE))
    _require(observability.get("KONG_STATUS_LISTEN") == "0.0.0.0:8100", "observability template must bind the private status listener")


def validate_inventory_gates(foundation: dict, root: Path = ROOT) -> None:
    inventory = load_json(root / "config/kong-production-route-inventory.v2.json")
    blocked = {item["route"]: item for item in inventory.get("activationBlockedRoutes", [])}
    for entry in foundation["routes"]:
        observed = [b for b in entry["bindings"] if b["source"] == "config/kong-production-route-inventory.v2.json"]
        if not observed:
            continue
        if entry["activation"] == "BLOCKED" and entry.get("inventoryGate") == "activationBlockedRoutes":
            _require(observed[0]["route"] in blocked,
                     f"route {entry['routeId']} is BLOCKED but the production inventory does not list it in activationBlockedRoutes")
    for name, item in blocked.items():
        entry = next((r for r in foundation["routes"] if any(b["route"] == name and b["source"] == "config/kong-production-route-inventory.v2.json" for b in r["bindings"])), None)
        _require(entry is not None and entry["activation"] == "BLOCKED", f"inventory blocks {name} but the registry does not")
        _require(item.get("activationAuthorized") is False, f"inventory activationBlockedRoutes entry {name} must not authorize activation")


def validate_foundation(root: Path = ROOT, foundation_path: Path | None = None) -> dict:
    foundation = load_json(foundation_path or (root / "config/kong-gateway-foundation.v1.json"))
    validate_registry_shape(foundation)
    validate_source_discovery(foundation, root)
    documents = load_sources(foundation, root)
    validate_sources(foundation, documents)
    validate_no_undocumented_routes(foundation, documents)
    services = validate_services(foundation, documents)
    materialized = validate_routes(foundation, documents, services)
    routes = _index(foundation["routes"], "routeId")
    overlaps = validate_precedence(foundation, routes, materialized)
    validate_plugins(foundation, documents)
    validate_environments(foundation, documents)
    validate_node(foundation, root)
    validate_inventory_gates(foundation, root)
    return {
        "foundation": foundation, "documents": documents, "services": services,
        "routes": routes, "materialized": materialized, "overlaps": overlaps,
    }


# --------------------------------------------------------------------------- rendering


def _fmt(values: Any) -> str:
    if values is None:
        return "*unspecified*"
    if isinstance(values, (tuple, list)):
        return ", ".join(f"`{v}`" for v in values) if values else "*none*"
    if isinstance(values, bool):
        return "true" if values else "false"
    return f"`{values}`"


def render_services(result: dict) -> str:
    rows = ["| Service | Env | Owner | Class | Upstream | Timeout | Retry | Auth | Rate | Size | Health | Lifecycle | Disposition | Findings |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(result["services"].values(), key=lambda e: (e["environment"], e["serviceId"])):
        up = entry["upstream"]
        rows.append("| " + " | ".join([
            f"`{entry['serviceId']}`", entry["environment"], entry["owner"], entry["upstreamClass"],
            f"`{up['protocol']}://{up['host']}:{up['port']}`", entry["timeoutProfile"], entry["retryProfile"],
            entry["authenticationProfile"], entry["rateLimitProfile"], entry["requestSizeProfile"], entry["healthProfile"],
            entry["lifecycle"], entry["disposition"], ", ".join(entry["acceptedFindings"]) or "—",
        ]) + " |")
    return "\n".join(rows)


def render_routes(result: dict) -> str:
    rows = ["| Route | Service | Env | Hosts | Paths | Methods | Strip | Preserve | Auth | Mechanism | Audience | Scopes | Rate | Size | Class | Lifecycle | Activation | Disposition | Findings |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for route_id, entry in sorted(result["routes"].items(), key=lambda kv: (kv[1]["environment"], kv[0])):
        route = result["materialized"][route_id]
        rows.append("| " + " | ".join([
            f"`{route_id}`", f"`{entry['serviceId']}`", entry["environment"], _fmt(route.hosts), _fmt(route.paths),
            _fmt(route.methods), _fmt(route.strip_path), _fmt(route.preserve_host), entry["authentication"],
            entry["mechanism"], _fmt(entry.get("audience")), _fmt(entry.get("requiredScopes") or None),
            entry["rateLimitProfile"], entry["requestSizeProfile"], entry["trafficClass"], entry["lifecycle"],
            entry["activation"], entry["disposition"], ", ".join(entry["acceptedFindings"]) or "—",
        ]) + " |")
    return "\n".join(rows)


def render_plugins(result: dict) -> str:
    rows = ["| Plugin | Kind | Auth | Priority | Allowed scopes | Owner | Purpose | Security impact | Ordering dependency | Environments | Configuration sources |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for entry in sorted(result["foundation"]["plugins"], key=lambda e: -e["priority"]):
        rows.append("| " + " | ".join([
            f"`{entry['plugin']}`", entry["kind"], "yes" if entry["authentication"] else "no", str(entry["priority"]),
            ", ".join(entry["allowedScopes"]), entry["owner"], entry["purpose"], entry["securityImpact"],
            entry["orderingDependency"], ", ".join(entry["environments"]), ", ".join(f"`{s}`" for s in entry["configurationSources"]),
        ]) + " |")
    return "\n".join(rows)


def render_conflicts(result: dict) -> str:
    rows = ["| Route A | Route B | Router winner | Resolution | Note |", "| --- | --- | --- | --- | --- |"]
    for conflict in result["foundation"]["precedence"]["knownConflicts"]:
        rows.append(f"| `{conflict['left']}` | `{conflict['right']}` | `{conflict['winner']}` | {conflict['resolution']} | {conflict['note']} |")
    return "\n".join(rows)


def render_drift(result: dict) -> str:
    rows = ["| Kind | Subject | Field | Observed (readback 2026-09-06) | Desired (contract) | Severity | Resolution |",
            "| --- | --- | --- | --- | --- | --- | --- |"]
    for item in result["foundation"]["knownDrift"]:
        rows.append(f"| {item['kind']} | `{item['subject']}` | `{item['field']}` | `{json.dumps(item['observed'])}` | `{json.dumps(item['desired'])}` | {item['severity']} | {item['resolution']} |")
    return "\n".join(rows)


RENDERERS = {
    "services": render_services, "routes": render_routes, "plugins": render_plugins,
    "conflicts": render_conflicts, "drift": render_drift,
}
MARKER = re.compile(r"(<!-- BEGIN GENERATED: (?P<name>[a-z]+) -->\n)(?P<body>.*?)(<!-- END GENERATED: (?P=name) -->)", re.DOTALL)


def sync_docs(result: dict, root: Path = ROOT, write: bool = False) -> list[str]:
    stale: list[str] = []
    for doc_path in result["foundation"]["generatedDocs"]:
        path = root / doc_path
        text = path.read_text(encoding="utf-8").replace("\r\n", "\n")

        def replace(match: re.Match) -> str:
            body = RENDERERS[match.group("name")](result)
            return match.group(1) + body + "\n" + match.group(4)

        updated = MARKER.sub(replace, text)
        if updated != text:
            stale.append(doc_path)
            if write:
                path.write_text(updated, encoding="utf-8", newline="\n")
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--write-docs", action="store_true", help="refresh generated registry tables in the docs")
    parser.add_argument("--summary", action="store_true", help="print a machine-readable summary")
    args = parser.parse_args(argv)
    result = validate_foundation()
    stale = sync_docs(result, write=args.write_docs)
    if stale and not args.write_docs:
        print("KONG_GATEWAY_FOUNDATION=FAIL generated documentation is stale: " + ", ".join(stale))
        return 1
    routes = result["routes"]
    print("KONG_GATEWAY_FOUNDATION=PASS")
    print(f"SOURCES={len(result['documents'])} SERVICES={len(result['services'])} ROUTES={len(routes)} "
          f"PLUGINS={len(result['foundation']['plugins'])} OVERLAPS={len(result['overlaps'])} "
          f"KNOWN_DRIFT={len(result['foundation']['knownDrift'])}")
    counts: dict[str, int] = {}
    for entry in routes.values():
        counts[entry["lifecycle"]] = counts.get(entry["lifecycle"], 0) + 1
    print("LIFECYCLE=" + ",".join(f"{k}:{v}" for k, v in sorted(counts.items())))
    print("RUNTIME_APPLY_AUTHORIZED=NO")
    if args.summary:
        print(json.dumps({
            "routes": {k: {"lifecycle": v["lifecycle"], "activation": v["activation"], "authentication": v["authentication"],
                           "findings": v["acceptedFindings"]} for k, v in routes.items()},
        }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FoundationError as error:
        print(f"KONG_GATEWAY_FOUNDATION=FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
