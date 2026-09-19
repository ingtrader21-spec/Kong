#!/usr/bin/env python3
"""Validate the Kong release supply chain against the release registry contract.

Static, source-only. Proves that the release and preflight workflows, the
release tools, the standby compose file and the standby Dockerfile all derive
the image authority from ``config/kong-release-registry-contract.v1.json``,
run with least privilege, publish only immutable digest-bound candidates with
attestations, prove the exact source they publish from, and can never turn a
failure into a success. Nothing here contacts a registry or a runtime.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ".github/workflows/release.yml"
PREFLIGHT_WORKFLOW = ".github/workflows/release-preflight.yml"
WORKFLOWS = (RELEASE_WORKFLOW, PREFLIGHT_WORKFLOW)
RELEASE_TOOLS = (
    "tools/generate_release_manifest.py", "tools/verify_release_candidate.py",
    "tools/verify_staging_certification.py", "tools/verify_release_evidence.py",
)
COMPOSE = "deploy/kong-production-standby/compose.standby.yaml"
DOCKERFILE = "deploy/kong-production-standby/auth-middleware/Dockerfile"
REQUIREMENTS = "deploy/kong-production-standby/auth-middleware/requirements.txt"
ALLOWED_PERMISSIONS = {"contents": "read", "packages": "write", "actions": "read"}
FORBIDDEN_PERMISSIONS = {"contents": "write", "actions": "write", "administration": "write", "id-token": "write",
                         "pull-requests": "write", "issues": "write", "deployments": "write"}
MUTABLE_TAGS = ("latest", "stable")
GHCR_LITERAL = re.compile(r"ghcr\.io/([A-Za-z0-9._-]+)/")
DIGEST_CHECK = r"^sha256:[0-9a-f]{64}$"


class SupplyChainError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SupplyChainError(message)


def load_contract(root: Path) -> dict:
    import importlib.util

    spec = importlib.util.spec_from_file_location("release_contract_under_validation", root / "tools/release_contract.py")
    module = importlib.util.module_from_spec(spec)
    # tools/release_contract.py validates the contract of its own tree at import and fails loudly.
    try:
        spec.loader.exec_module(module)
    except (ValueError, KeyError, OSError) as error:  # ContractError is a ValueError
        raise SupplyChainError(f"registry contract: {error}") from error
    contract = module.load_contract(root / "config/kong-release-registry-contract.v1.json")
    module.load_evidence_contract(root / "config/kong-release-evidence-contract.v1.json")
    return contract


def _steps(job: dict) -> list[dict]:
    return list(job.get("steps") or [])


def _triggers(document: dict) -> dict:
    # PyYAML reads the bare ``on`` key as the boolean True.
    return document.get("on") or document.get(True) or {}


def validate_workflow(root: Path, path: str, contract: dict, *, preflight: bool) -> dict:
    text = (root / path).read_text(encoding="utf-8")
    document = yaml.safe_load(text)
    image = contract["registry"]["image"]
    namespace = contract["registry"]["namespace"]
    former = [f["fullName"].split("/", 1)[0] for f in contract["repository"].get("formerNames", [])]
    # --- permissions: least privilege, no escalation, no OIDC unless attesting through GitHub
    permissions = document.get("permissions")
    require(isinstance(permissions, dict), f"{path}: top-level permissions must be explicit")
    for scope, level in permissions.items():
        require(ALLOWED_PERMISSIONS.get(scope) == level, f"{path}: permission {scope}: {level} is not the least-privilege set")
    require(permissions.get("packages") == "write" and permissions.get("contents") == "read",
            f"{path}: release workflows need exactly contents: read and packages: write")
    for scope, level in FORBIDDEN_PERMISSIONS.items():
        require(permissions.get(scope) != level, f"{path}: forbidden permission {scope}: {level}")
    for job_name, job in (document.get("jobs") or {}).items():
        require("permissions" not in job, f"{path}: job {job_name} must not widen permissions")
    # --- no owner literal, no mutable tag, no continue-on-error
    for owner in former:
        require(owner not in text, f"{path}: stale former owner literal {owner!r}")
    for literal in GHCR_LITERAL.findall(text):
        require(literal == namespace, f"{path}: ghcr.io namespace literal {literal!r} is not the contract namespace {namespace!r}")
    for tag in MUTABLE_TAGS:
        require(tag not in text, f"{path}: mutable tag {tag!r} must never appear in a release workflow")
    require("continue-on-error" not in text, f"{path}: continue-on-error would turn a release failure into a success")
    require("secrets." not in text, f"{path}: registry authentication must use github.token, never a stored credential")
    require('printf \'%s\' "${GHCR_TOKEN}" | docker login ghcr.io --username "${GITHUB_ACTOR}" --password-stdin' in text,
            f"{path}: docker login must authenticate the workflow actor with github.token")
    require("GHCR_TOKEN: ${{ github.token }}" in text, f"{path}: GHCR_TOKEN must be github.token")
    # --- contract binding precedes authentication; exact source proven; evidence verified
    runs = "\n".join(step.get("run", "") for job in (document.get("jobs") or {}).values() for step in _steps(job))
    bind = runs.find("tools/release_contract.py")
    login = runs.find("docker login ghcr.io")
    require(bind >= 0 and login >= 0 and bind < login, f"{path}: the registry contract must be bound before docker login")
    require('--assert-repository "${GITHUB_REPOSITORY}"' in runs and '--assert-owner "${GITHUB_REPOSITORY_OWNER}"' in runs,
            f"{path}: the contract must be asserted against GITHUB_REPOSITORY and GITHUB_REPOSITORY_OWNER")
    require('test "${image}" = "ghcr.io/${GITHUB_REPOSITORY_OWNER,,}/kong-standby-auth"' in runs,
            f"{path}: the image namespace must be re-derived from the running repository owner")
    require('test "$(git rev-parse HEAD)" = "${EXPECTED_SHA}"' in runs, f"{path}: exact source identity must be proven")
    require('test -z "$(git status --porcelain)"' in runs, f"{path}: a dirty tree must never be published")
    require("tools/verify_standby_image.py" in runs, f"{path}: the image must be verified before publication")
    require("--provenance=mode=max" in runs and "--sbom=true" in runs, f"{path}: publication must attach provenance and SBOM")
    require("--push" in runs and "--metadata-file" in runs, f"{path}: publication must capture the pushed digest")
    require("containerimage.digest" in runs and '[[ "${digest}" =~ ' + DIGEST_CHECK + " ]]" in runs,
            f"{path}: the pushed digest must be captured from the build metadata and validated as sha256")
    require('test "${remote}" = "${LOCAL_DIGEST}"' in runs, f"{path}: the registry digest must equal the built digest")
    require("tools/extract_image_attestations.py" in runs, f"{path}: attestations must be extracted and bound")
    require("tools/generate_release_manifest.py" in runs and "tools/verify_release_evidence.py" in runs,
            f"{path}: release evidence must be generated and verified")
    expected_tag = 'tag="${STANDBY_IMAGE_REPOSITORY}:preflight-sha-${EXPECTED_SHA}"' if preflight \
        else 'tag="${STANDBY_IMAGE_REPOSITORY}:sha-${EXPECTED_SHA}"'
    require(expected_tag in runs, f"{path}: the published tag must be the immutable {'preflight ' if preflight else ''}sha tag")
    if preflight:
        require(_triggers(document).get("pull_request") is not None, f"{path}: preflight runs on pull_request")
        job = document["jobs"]["release-preflight"]
        require(job.get("if") == "github.event.pull_request.head.repo.full_name == github.repository",
                f"{path}: preflight must refuse fork pull requests")
        require("--release-stage pull-request-preflight" in runs, f"{path}: preflight evidence must carry the preflight stage")
    else:
        require(sorted(_triggers(document)["push"]["branches"]) == ["main", "production", "staging"], f"{path}: release runs only on environment branches")
        require('test "${GITHUB_REF_PROTECTED}" = true' in runs, f"{path}: release requires a protected ref")
        job = document["jobs"]["release-evidence"]
        for step in _steps(job):
            run = step.get("run", "")
            if "docker buildx build" in run or "${KONG_IMAGE_REF}" in run:
                require(step.get("if") == "github.ref_name == 'main'", f"{path}: build/publish step {step.get('name')!r} must be main-only")
    return {"path": path, "permissions": permissions}


def validate_tools(root: Path, contract: dict) -> None:
    former = [f["fullName"] for f in contract["repository"].get("formerNames", [])]
    former_owners = [name.split("/", 1)[0] for name in former]
    for tool in RELEASE_TOOLS:
        text = (root / tool).read_text(encoding="utf-8")
        require("ghcr.io/" not in text, f"{tool}: image authority must come from tools/release_contract.py, not a literal")
        for owner in former_owners:
            require(owner not in text, f"{tool}: stale former owner literal {owner!r}")
        # The staging verifier takes REPOSITORY from verify_release_candidate, which derives it from the contract.
        require("release_contract" in text or "from tools.verify_release_candidate import" in text,
                f"{tool}: must derive its repository/image authority from the release contract")


def validate_compose_and_image(root: Path, contract: dict) -> None:
    image = contract["registry"]["image"]
    compose = (root / COMPOSE).read_text(encoding="utf-8")
    require("build:" not in compose, f"{COMPOSE}: deploy-time builds are forbidden")
    require(f"image: {image}@${{KONG_STANDBY_AUTH_IMAGE_DIGEST:?" in compose,
            f"{COMPOSE}: the standby image must be the contract image pinned by digest")
    for literal in GHCR_LITERAL.findall(compose):
        require(literal == contract["registry"]["namespace"], f"{COMPOSE}: namespace literal {literal!r} is not the contract namespace")
    dockerfile = (root / DOCKERFILE).read_text(encoding="utf-8")
    first = next(line for line in dockerfile.splitlines() if line.startswith("FROM "))
    require("@sha256:" in first, f"{DOCKERFILE}: the base image must be pinned by digest")
    require(re.search(r"^USER 65532:65532\s*$", dockerfile, re.M) is not None, f"{DOCKERFILE}: the image must run as the non-root standby user")
    require("ADD http" not in dockerfile and "curl " not in dockerfile and "wget " not in dockerfile,
            f"{DOCKERFILE}: no mutable network fetch may enter the image")
    for line in (root / REQUIREMENTS).read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            require("==" in line, f"{REQUIREMENTS}: unpinned requirement {line!r}")


def validate(root: Path = ROOT) -> dict:
    contract = load_contract(root)
    release = validate_workflow(root, RELEASE_WORKFLOW, contract, preflight=False)
    preflight = validate_workflow(root, PREFLIGHT_WORKFLOW, contract, preflight=True)
    validate_tools(root, contract)
    validate_compose_and_image(root, contract)
    return {"contract": contract, "release": release, "preflight": preflight}


def main() -> int:
    try:
        result = validate()
    except SupplyChainError as error:
        print(f"KONG_RELEASE_SUPPLY_CHAIN=FAIL {error}")
        return 1
    registry = result["contract"]["registry"]
    print("KONG_RELEASE_SUPPLY_CHAIN=PASS")
    print(f"REGISTRY={registry['host']} NAMESPACE={registry['namespace']} PACKAGE={registry['package']}")
    print(f"IMAGE={registry['image']} REPOSITORY={result['contract']['repository']['fullName']}")
    print("PERMISSIONS=contents:read,packages:write,actions:read IMMUTABLE_TAGS=sha-<sha>,preflight-sha-<sha>")
    print("RUNTIME_APPLY_AUTHORIZED=NO PROVIDER_EFFECTS_ENABLED=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
