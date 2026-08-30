#!/usr/bin/env python3
"""Collect sanitized, read-only Kong-to-Middleware topology evidence.

The collector never changes containers, networks, routes, firewall rules,
configuration files, or services. It resolves the current, ambiguous, and
proposed TLS hostnames from inside the selected Kong container, records only
approved Docker metadata, and performs anonymous TLS/readiness probes. No
environment values, credentials, request bodies, response bodies, logs, or
decrypted secrets are emitted. When ``--output`` is supplied, the only file
write is the explicitly requested evidence artifact.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[2]
CURRENT_RUNTIME_HOST = "appolon-middleware-integration-api"
AMBIGUOUS_ALIAS = "middleware-integration-api"
PROBE_PATH = (
    "/v1/integrations/n8n/operations/"
    "00000000-0000-0000-0000-000000000000"
)
FAIL_CLOSED_HTTP_STATUSES = {401, 403, 404}
DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
SHA40 = re.compile(r"[0-9a-f]{40}\Z")
NON_KONG_IDENTITY_TOKENS = {"postgres", "database", "backup"}


class EvidenceError(RuntimeError):
    """Raised when safe evidence collection cannot proceed."""


def valid_dns_name(value: str) -> bool:
    if not isinstance(value, str) or not DNS_NAME.fullmatch(value):
        return False
    if value in {"localhost", "invalid"} or value.endswith(
        (".localhost", ".invalid", ".example", ".test")
    ):
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return True
    return False


def run(
    command: Sequence[str],
    *,
    timeout: int = 15,
    check: bool = True,
    stdin: str | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=stdin,
            cwd=cwd,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"command unavailable or timed out: {command[0]}") from exc
    if check and result.returncode != 0:
        raise EvidenceError(f"read-only command failed: {command[0]}")
    return result


def container_id_hash(container_id: str) -> str:
    return hashlib.sha256(container_id.encode("utf-8")).hexdigest()


def parse_ipv4(text: str) -> list[str]:
    addresses: set[str] = set()
    for line in text.splitlines():
        parts = line.split(maxsplit=1)
        first = parts[0] if parts else ""
        try:
            address = ipaddress.ip_address(first)
        except ValueError:
            continue
        if address.version == 4:
            addresses.add(str(address))
    return sorted(addresses, key=ipaddress.ip_address)


def verified_source_sha(expected: str) -> str:
    """Bind evidence to the exact, clean repository checkout being executed."""
    top_level_text = run(
        ["git", "rev-parse", "--show-toplevel"], cwd=ROOT
    ).stdout.strip()
    try:
        top_level = Path(top_level_text).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EvidenceError("checked-out repository root cannot be resolved") from exc
    if top_level != ROOT.resolve():
        raise EvidenceError("collector is not running from its repository root")

    actual = run(["git", "rev-parse", "HEAD^{commit}"], cwd=ROOT).stdout.strip()
    if not SHA40.fullmatch(actual) or actual != expected:
        raise EvidenceError("supplied source SHA does not match the checked-out repository")

    status = run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT
    ).stdout.strip()
    if status:
        raise EvidenceError("checked-out repository has uncommitted or untracked changes")

    tracked_flags = run(["git", "ls-files", "-v"], cwd=ROOT).stdout.splitlines()
    if any(line and (line[0].islower() or line[0] == "S") for line in tracked_flags):
        raise EvidenceError("checked-out repository uses hidden or skipped tracked-file state")

    return actual


def inspect_container(container: str) -> dict[str, Any]:
    result = run(["docker", "inspect", container], check=False)
    if result.returncode != 0:
        raise EvidenceError("requested container does not exist")
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise EvidenceError("docker inspect returned invalid container metadata") from exc
    if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], dict):
        raise EvidenceError("docker inspect did not identify exactly one container")
    return decoded[0]


def metadata_identifies_kong(row: dict[str, Any]) -> bool:
    config = row.get("Config") or {}
    labels = config.get("Labels") or {}
    service_label = str(labels.get("com.docker.compose.service") or "").casefold()
    name = str(row.get("Name") or "").casefold()
    image = str(config.get("Image") or "").casefold()
    combined = " ".join((service_label, name, image))
    if any(token in combined for token in NON_KONG_IDENTITY_TOKENS):
        return False
    return "kong" in service_label or "kong" in name or "kong" in image


def find_kong_container(requested: str | None) -> str:
    if requested:
        row = inspect_container(requested)
        if (row.get("State") or {}).get("Running") is not True:
            raise EvidenceError("requested Kong container is not running")
        if not metadata_identifies_kong(row):
            raise EvidenceError("requested container is not identified as Kong")
        return requested

    container_ids = [
        line.strip()
        for line in run(["docker", "ps", "--format", "{{.ID}}"])
        .stdout.splitlines()
        if line.strip()
    ]
    if not container_ids:
        raise EvidenceError("one running Kong container was not identified")
    result = run(["docker", "inspect", *container_ids])
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise EvidenceError("docker inspect returned invalid container metadata") from exc
    if not isinstance(decoded, list):
        raise EvidenceError("docker inspect returned an invalid document")
    candidates = [
        str(row.get("Id") or "")
        for row in decoded
        if isinstance(row, dict)
        and (row.get("State") or {}).get("Running") is True
        and metadata_identifies_kong(row)
    ]
    candidates = [value for value in candidates if re.fullmatch(r"[0-9a-f]{64}", value)]
    if len(candidates) != 1:
        raise EvidenceError("one running Kong container was not identified")
    return candidates[0]


def exact_container_id(container: str) -> str:
    container_id = run(
        ["docker", "inspect", container, "--format", "{{.Id}}"]
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", container_id):
        raise EvidenceError("Kong container does not have a canonical Docker ID")
    return container_id


def resolve_from_kong(kong_container: str, hostname: str) -> list[str]:
    result = run(
        ["docker", "exec", kong_container, "getent", "ahostsv4", hostname],
        check=False,
    )
    if result.returncode != 0:
        return []
    return parse_ipv4(result.stdout)


def inspect_running_containers() -> list[dict[str, Any]]:
    container_ids = [
        line.strip()
        for line in run(["docker", "ps", "--format", "{{.ID}}"])
        .stdout.splitlines()
        if line.strip()
    ]
    if not container_ids:
        return []
    result = run(["docker", "inspect", *container_ids])
    decoded = json.loads(result.stdout)
    if not isinstance(decoded, list):
        raise EvidenceError("docker inspect returned an invalid document")
    return [row for row in decoded if isinstance(row, dict)]


def alias_candidates(
    inspected: list[dict[str, Any]], hostname: str
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for row in inspected:
        networks = ((row.get("NetworkSettings") or {}).get("Networks") or {})
        if not isinstance(networks, dict):
            continue
        matched_networks: list[str] = []
        matched_ips: list[str] = []
        for network_name, network in networks.items():
            if not isinstance(network, dict):
                continue
            aliases = network.get("Aliases") or []
            if hostname not in aliases:
                continue
            matched_networks.append(str(network_name))
            ip_value = str(network.get("IPAddress") or "")
            try:
                address = ipaddress.ip_address(ip_value)
            except ValueError:
                continue
            if address.version == 4:
                matched_ips.append(str(address))
        if not matched_networks:
            continue
        container_id = str(row.get("Id") or "")
        configured_image = str((row.get("Config") or {}).get("Image") or "")
        image_id = str(row.get("Image") or "")
        candidates.append(
            {
                "container_id_sha256": container_id_hash(container_id),
                "configured_image": configured_image,
                "image_id": image_id,
                "networks": sorted(set(matched_networks)),
                "ipv4": sorted(set(matched_ips), key=ipaddress.ip_address),
            }
        )
    return sorted(candidates, key=lambda row: row["container_id_sha256"])


def command_exists(kong_container: str, command: str) -> bool:
    result = run(
        ["docker", "exec", kong_container, "sh", "-c", f"command -v {command}"],
        check=False,
    )
    return result.returncode == 0


def tls_probe(kong_container: str, hostname: str) -> dict[str, Any]:
    if not command_exists(kong_container, "openssl"):
        return {
            "tool_available": False,
            "certificate_verified": False,
            "hostname_verified": False,
        }
    result = run(
        [
            "docker",
            "exec",
            "-i",
            kong_container,
            "openssl",
            "s_client",
            "-connect",
            f"{hostname}:443",
            "-servername",
            hostname,
            "-verify_return_error",
            "-verify_hostname",
            hostname,
            "-brief",
        ],
        timeout=20,
        check=False,
        stdin="",
    )
    verified = result.returncode == 0
    return {
        "tool_available": True,
        "certificate_verified": verified,
        "hostname_verified": verified,
    }


def readiness_probe(kong_container: str, hostname: str) -> dict[str, Any]:
    if not command_exists(kong_container, "curl"):
        return {"tool_available": False, "http_status": None, "fail_closed": False}
    result = run(
        [
            "docker",
            "exec",
            kong_container,
            "curl",
            "--silent",
            "--show-error",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}",
            "--connect-timeout",
            "3",
            "--max-time",
            "8",
            f"https://{hostname}{PROBE_PATH}",
        ],
        timeout=15,
        check=False,
    )
    try:
        status = int(result.stdout.strip())
    except ValueError:
        status = None
    return {
        "tool_available": True,
        "http_status": status,
        "fail_closed": result.returncode == 0 and status in FAIL_CLOSED_HTTP_STATUSES,
    }


def identity_hashes(candidates: list[dict[str, Any]]) -> set[str]:
    return {str(row["container_id_sha256"]) for row in candidates}


def candidate_ipv4(candidates: list[dict[str, Any]]) -> set[str]:
    addresses: set[str] = set()
    for row in candidates:
        for value in row.get("ipv4") or []:
            try:
                address = ipaddress.ip_address(str(value))
            except ValueError:
                continue
            if address.version == 4:
                addresses.add(str(address))
    return addresses


def current_runtime_is_unique(
    current_ips: list[str], current_candidates: list[dict[str, Any]]
) -> bool:
    if len(current_candidates) != 1 or not current_ips:
        return False
    hashes = identity_hashes(current_candidates)
    return len(hashes) == 1 and set(current_ips).issubset(
        candidate_ipv4(current_candidates)
    )


def tls_targets_exclusively_match_current_runtime(
    *,
    current_ips: list[str],
    current_candidates: list[dict[str, Any]],
    tls_ips: list[str],
    tls_candidates: list[dict[str, Any]],
) -> bool:
    """Require every TLS address/candidate to belong to the one current runtime."""
    if not current_runtime_is_unique(current_ips, current_candidates) or not tls_ips:
        return False

    current_hashes = identity_hashes(current_candidates)
    tls_resolved = set(tls_ips)
    if tls_candidates:
        if identity_hashes(tls_candidates) != current_hashes:
            return False
        return tls_resolved.issubset(candidate_ipv4(tls_candidates))

    # A non-Docker private DNS name may have no alias candidate. In that case
    # every resolved address must still be an address of the verified runtime.
    return tls_resolved.issubset(candidate_ipv4(current_candidates))


def build_evidence(
    *,
    source_sha: str,
    kong_container: str,
    tls_host: str,
) -> dict[str, Any]:
    inspected = inspect_running_containers()
    current_ips = resolve_from_kong(kong_container, CURRENT_RUNTIME_HOST)
    ambiguous_ips = resolve_from_kong(kong_container, AMBIGUOUS_ALIAS)
    tls_ips = resolve_from_kong(kong_container, tls_host)
    current_candidates = alias_candidates(inspected, CURRENT_RUNTIME_HOST)
    ambiguous_candidates = alias_candidates(inspected, AMBIGUOUS_ALIAS)
    tls_candidates = alias_candidates(inspected, tls_host)

    current_hashes = identity_hashes(current_candidates)
    ambiguous_hashes = identity_hashes(ambiguous_candidates)
    tls_result = tls_probe(kong_container, tls_host)
    readiness = readiness_probe(kong_container, tls_host)

    ambiguous_not_current = not (
        set(current_ips) & set(ambiguous_ips)
        or current_hashes & ambiguous_hashes
    )
    current_unique = current_runtime_is_unique(current_ips, current_candidates)
    tls_same_runtime = tls_targets_exclusively_match_current_runtime(
        current_ips=current_ips,
        current_candidates=current_candidates,
        tls_ips=tls_ips,
        tls_candidates=tls_candidates,
    )
    gates = {
        "source_sha_verified": True,
        "current_runtime_unique": current_unique,
        "ambiguous_alias_not_current_runtime": ambiguous_not_current,
        "tls_candidate_resolves": bool(tls_ips),
        "tls_candidate_same_runtime": tls_same_runtime,
        "tls_certificate_verified": tls_result["certificate_verified"],
        "tls_hostname_verified": tls_result["hostname_verified"],
        "readiness_response_fail_closed": readiness["fail_closed"],
        "no_runtime_mutations_performed": True,
    }

    return {
        "schema_version": "1.0",
        "status": "CANDIDATE_PASS" if all(gates.values()) else "CANDIDATE_BLOCKED",
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source_sha": source_sha,
        "kong_container_id_sha256": container_id_hash(
            exact_container_id(kong_container)
        ),
        "current_runtime": {
            "host": CURRENT_RUNTIME_HOST,
            "resolved_ipv4": current_ips,
            "candidates": current_candidates,
        },
        "ambiguous_alias": {
            "host": AMBIGUOUS_ALIAS,
            "resolved_ipv4": ambiguous_ips,
            "candidates": ambiguous_candidates,
        },
        "tls_candidate": {
            "host": tls_host,
            "port": 443,
            "resolved_ipv4": tls_ips,
            "candidates": tls_candidates,
            "tls": tls_result,
            "readiness": readiness,
        },
        "gates": gates,
        "secrets_captured": False,
        "runtime_mutations_performed": False,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--tls-host",
        default=os.environ.get("MIDDLEWARE_TLS_HOST"),
        help="Proposed private Middleware TLS DNS name; never include a scheme.",
    )
    parser.add_argument("--kong-container")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.tls_host or not valid_dns_name(args.tls_host):
        print("TOPOLOGY_EVIDENCE=FAIL")
        print("ERROR=--tls-host must be a canonical DNS name", file=sys.stderr)
        return 2
    if args.tls_host == AMBIGUOUS_ALIAS:
        print("TOPOLOGY_EVIDENCE=FAIL")
        print("ERROR=ambiguous Middleware alias is forbidden", file=sys.stderr)
        return 2
    if not SHA40.fullmatch(args.source_sha):
        print("TOPOLOGY_EVIDENCE=FAIL")
        print("ERROR=--source-sha must be an exact 40-character Git SHA", file=sys.stderr)
        return 2

    try:
        exact_sha = verified_source_sha(args.source_sha)
        kong_container = find_kong_container(args.kong_container)
        evidence = build_evidence(
            source_sha=exact_sha,
            kong_container=kong_container,
            tls_host=args.tls_host,
        )
    except (EvidenceError, json.JSONDecodeError) as exc:
        print("TOPOLOGY_EVIDENCE=FAIL")
        print(f"ERROR={exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    print(f"TOPOLOGY_EVIDENCE={evidence['status']}", file=sys.stderr)
    return 0 if evidence["status"] == "CANDIDATE_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
