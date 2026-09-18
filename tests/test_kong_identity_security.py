"""Mission 2 — identity, authentication and API access security enforcement.

Positive tests prove the committed access policy, authentication profiles and
foundation agree and that every route carries an explicit access class,
issuer, audience, scope, party and identity-propagation posture. Negative
tests mutate isolated copies of the repository and prove the canonical
validator fails closed on: an unclassified route, a protected route without
authentication, a public route that is not allowlisted, a wrong or wildcard
issuer, a missing/wrong/wildcard audience, a missing required scope, identity
headers treated as authority, arbitrary tenant-header trust, a committed
client secret, a global authentication plugin and an authentication downgrade.

Mission 1 dependencies (PR #105) are reported as M1_DEPENDENCY_PENDING, never
as Mission 2 defects, and never as completed. Nothing here contacts a Kong node.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/validate_kong_foundation.py"
SPEC = importlib.util.spec_from_file_location("kong_foundation_validator_m2", MODULE_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)

FOUNDATION = "config/kong-gateway-foundation.v1.json"
POLICY = "config/kong-access-policy.v1.json"
PROFILES = "config/kong-authentication-profiles.v1.json"
CONTROL_PLANE = "deploy/kong/control-plane.yml"
COPIED = ("config", "deploy", "kong", "docs", "scripts", "tests", "tools", "operations", "orbit", "contracts", ".github")
BASE: dict[str, Path] = {}

M1_RECONCILED = (ROOT / "config/kong-middleware-authority.v2.json").is_file()
M1_PENDING_REASON = "M1_DEPENDENCY_PENDING: PR #105 (fb353cb) retires the appolon-middleware-integration-api:8080 alias; awaiting independent approval"


@pytest.fixture(scope="module")
def base_copy(tmp_path_factory) -> Path:
    base = tmp_path_factory.mktemp("kong-m2-base")
    for name in COPIED:
        source = ROOT / name
        if source.is_dir():
            shutil.copytree(source, base / name, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    BASE["root"] = base
    return base


@pytest.fixture
def repo(base_copy, tmp_path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(base_copy, root)
    return root


def read_json(root: Path, path: str) -> dict:
    return json.loads((root / path).read_text(encoding="utf-8"))


def write_json(root: Path, path: str, document: dict) -> None:
    (root / path).write_text(json.dumps(document, indent=2), encoding="utf-8")


def read_yaml(root: Path, path: str) -> dict:
    return yaml.safe_load((root / path).read_text(encoding="utf-8"))


def write_yaml(root: Path, path: str, document: dict) -> None:
    (root / path).write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def expect_failure(root: Path, match: str) -> None:
    with pytest.raises(validator.FoundationError, match=match):
        validator.validate_foundation(root=root)


def policy_entry(document: dict, route_id: str) -> dict:
    return next(r for r in document["routes"] if r["routeId"] == route_id)


# --------------------------------------------------------------------------- positive


def test_access_policy_validates_and_every_route_is_classified():
    result = validator.validate_foundation(root=ROOT)
    policy, profiles = result["policy"], result["profiles"]
    assert policy["runtimeApplyAuthorized"] is False and profiles["runtimeApplyAuthorized"] is False
    assert {r["routeId"] for r in policy["routes"]} == set(result["routes"])
    for item in policy["routes"]:
        assert item["accessClass"] in validator.ACCESS_CLASSES
        assert item["authenticationProfile"] in profiles["profiles"]
        assert item["issuerProfile"] in profiles["issuerProfiles"]
        assert item["audienceProfile"] in profiles["audienceProfiles"]
        assert item["identityPropagation"] in profiles["identityPropagationProfiles"]
        assert item["tenantPolicy"] in profiles["tenantPolicies"]
        assert isinstance(item["requiredScopes"], list)
    assert result["secret_scan"] == 0


def test_intentional_public_routes_are_allowlisted_read_only_or_legacy():
    result = validator.validate_foundation(root=ROOT)
    policy = result["policy"]
    allow = {i["routeId"] for i in policy["publicAllowlist"]}
    public = {i["routeId"] for i in policy["routes"] if i["accessClass"] == "PUBLIC"}
    assert allow == public
    for route_id in public:
        route = result["materialized"][route_id]
        entry = result["routes"][route_id]
        mutating = set(route.methods or ()) & validator.MUTATION_METHODS
        assert not mutating or entry["lifecycle"] in ("LEGACY", "RETIRE_CANDIDATE"), route_id
    # the Mission 1 critical finding stays visible: blocked, not public, not resolved
    mail = policy_entry(policy, "codestra-mail-api")
    assert mail["accessClass"] == "ADMIN_INTERNAL" and mail["authenticationProfile"] == "BLOCKED_NONE_V1"
    assert result["routes"]["codestra-mail-api"]["activation"] == "BLOCKED"
    assert "codestra-mail-api" not in allow


def test_protected_routes_bind_issuer_audience_scopes_and_parties():
    result = validator.validate_foundation(root=ROOT)
    policy, profiles = result["policy"], result["profiles"]
    for item in policy["routes"]:
        entry = result["routes"][item["routeId"]]
        profile = profiles["profiles"][item["authenticationProfile"]]
        if item["accessClass"] == "PUBLIC" or profile["strength"] == 0:
            continue
        if profile["issuerProfile"] == "environment":
            issuer = profiles["issuerProfiles"][item["issuerProfile"]]
            assert issuer["environment"] == entry["environment"]
            assert issuer["algorithms"] == ["RS256"] and issuer["clockSkewSeconds"] == 0
        if entry["mechanism"] in validator.load_json(ROOT / FOUNDATION)["debtRules"]["tokenMechanisms"]:
            assert profiles["audienceProfiles"][item["audienceProfile"]]["audience"] not in (None, "*")
        assert item["requiredScopes"] == entry.get("requiredScopes", [])
        assert all("*" not in scope for scope in item["requiredScopes"])
        if profile["authorizedParties"] == "explicit":
            assert item["authorizedParties"]


def test_client_id_equals_audience_only_where_contractually_defined():
    result = validator.validate_foundation(root=ROOT)
    audiences = result["profiles"]["audienceProfiles"]
    for name, aud in audiences.items():
        if aud["clientIdIsAudience"]:
            assert aud["contractuallyDefinedBy"], name
    for item in result["policy"]["routes"]:
        if audiences[item["audienceProfile"]]["clientIdIsAudience"]:
            assert "AUDIENCE_IS_CLIENT_ID" in result["routes"][item["routeId"]]["acceptedFindings"]


def test_human_service_admin_and_internal_identities_are_separated():
    result = validator.validate_foundation(root=ROOT)
    for item in result["policy"]["routes"]:
        entry = result["routes"][item["routeId"]]
        if entry["activation"] == "BLOCKED":
            continue
        if item["accessClass"] == "ADMIN_INTERNAL":
            assert item["principalClasses"] == ["ADMIN"]
            assert "platform.admin" in item["requiredScopes"]
        if item["accessClass"] in ("SERVICE_AUTHENTICATED", "INTERNAL") and entry["lifecycle"] != "DESIGN_ONLY":
            assert "HUMAN" not in item["principalClasses"], item["routeId"]
        if "HUMAN" in item["principalClasses"] and entry["lifecycle"] != "DESIGN_ONLY":
            assert item["accessClass"] == "AUTHENTICATED", item["routeId"]


def test_identity_headers_are_never_authority_and_unstripped_routes_are_explicit():
    result = validator.validate_foundation(root=ROOT)
    policy, profiles = result["policy"], result["profiles"]
    assert policy["identityHeaders"]["headerAuthorityAllowed"] is False
    never = set(policy["identityHeaders"]["neverTrustedFromClients"])
    for header in ("X-User-ID", "X-Username", "X-Email", "X-Roles", "X-Scopes", "X-Consumer-ID", "X-Authenticated-UserID"):
        assert header in never
    for item in policy["routes"]:
        prop = profiles["identityPropagationProfiles"][item["identityPropagation"]]
        assert prop["stripsClientIdentity"] or "IDENTITY_HEADERS_NOT_STRIPPED" in item["acceptedFindings"]
        assert "HEADER_AUTHORITY" not in item["tenantPolicy"] or "CLAIM_AUTHORITY" in item["tenantPolicy"]


def test_guards_strip_before_minting_and_never_log_or_echo_tokens():
    for lua in ("deploy/kong/scope-policy.lua", "deploy/kong/calling-policy.lua", "deploy/kong/moneybee-identity-policy.lua"):
        text = (ROOT / lua).read_text(encoding="utf-8")
        assert text.index("clear_header") < text.index("set_header"), lua
        assert "kong.log" not in text and "ngx.log" not in text, lua
        # every exit body is a constant table: no token, claim or header value is echoed
        for body in re.findall(r"kong\.response\.exit\(\d+,\s*(\{.*?\})\)", text):
            assert "token" not in body and "claims." not in body and "header" not in body, (lua, body)
    for handler in ("codestra-authz", "codestra-request-context", "codestra-webhook-verifier"):
        text = (ROOT / f"deploy/kong/plugins/{handler}/handler.lua").read_text(encoding="utf-8")
        assert "kong.log" not in text and "ngx.log" not in text, handler


def test_token_and_cache_settings_are_bounded_and_vault_backed():
    result = validator.validate_foundation(root=ROOT)
    cache = result["profiles"]["tokenCachePolicies"]["OIDC_CACHE_V1"]
    assert cache["cacheTokensSalt"].startswith("{vault://env/") and cache["saltInGit"] is False
    assert 0 < cache["cacheTtlSeconds"] <= result["profiles"]["rules"]["maximumCacheTtlSeconds"]
    control_plane = read_yaml(ROOT, CONTROL_PLANE)
    oidc = next(p for p in control_plane["services"][0]["plugins"] if p["name"] == "openid-connect")["config"]
    assert oidc["cache_tokens_salt"] == "{vault://env/kong-oidc-cache-tokens-salt}"
    assert oidc.get("leeway", 0) == 0 and "anonymous" not in oidc
    assert oidc["audience"] == ["codestra-control-plane"] and oidc["auth_methods"] == ["bearer"]


def test_evidence_and_templates_contain_no_credential_values():
    markers = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ|BEGIN (?:RSA |EC |)PRIVATE KEY|client_secret\"?\s*[:=]\s*\"[A-Za-z0-9]{16,}")
    for path in ("docs/evidence/PRODUCTION_ROUTE_READBACK_20260906.json", "docs/evidence/PRODUCTION_HEAD_CANARY_20260906.json",
                 "deploy/kong/runtime.env.example", "deploy/kong/kong.conf.example", "kong/plugins/oidc/keycloak.yml"):
        assert not markers.search((ROOT / path).read_text(encoding="utf-8")), path
    evidence = read_json(ROOT, "docs/evidence/PRODUCTION_ROUTE_READBACK_20260906.json")
    assert evidence["secretsCaptured"] is False
    assert validator.scan_secrets(ROOT) == []


def test_logging_policy_and_admin_isolation_are_preserved():
    result = validator.validate_foundation(root=ROOT)
    logging = result["policy"]["logging"]
    for header in ("Authorization", "Cookie", "Set-Cookie", "access_token", "refresh_token", "id_token", "client_secret"):
        assert header in logging["neverPersisted"]
    assert logging["logPluginsRegistered"] == []
    assert not {p["plugin"] for p in result["foundation"]["plugins"]} & {"file-log", "http-log", "tcp-log", "udp-log", "syslog"}
    compose = read_yaml(ROOT, "deploy/kong/compose.kong.yaml")["services"]["kong-gateway"]
    assert compose["environment"]["KONG_ADMIN_LISTEN"] == "127.0.0.1:8001"
    assert compose["environment"]["KONG_ADMIN_GUI_LISTEN"] == "off"
    assert all(str(p).startswith("127.0.0.1:8000:") for p in compose["ports"])


# --------------------------------------------------------------------------- Mission 1 dependency (reported, never falsified)


def test_mission1_dependency_state_is_reported_not_hidden():
    result = validator.validate_foundation(root=ROOT)
    status = validator.m1_dependency_status(result["foundation"], ROOT)
    assert status["state"] in ("MERGED", "M1_DEPENDENCY_PENDING")
    assert status["reconciled"] == M1_RECONCILED
    dependent = [i for i in result["policy"]["routes"] if i.get("m1Dependency")]
    assert dependent, "routes bound to the transitional alias must declare the M1 dependency"
    assert result["policy"]["m1Dependency"]["pullRequest"] == 105


@pytest.mark.xfail(not M1_RECONCILED, reason=M1_PENDING_REASON, strict=True)
def test_middleware_8080_alias_is_retired_after_mission1_reconciliation():
    # Strict: when PR #105 lands this must start passing, at which point the
    # transitional alias, the m1Dependency markers and this guard are removed.
    result = validator.validate_foundation(root=ROOT)
    aliases = result["foundation"]["boundaryRules"]["middlewareUpstreamAliases"]
    assert not [a for a in aliases if a["port"] == 8080]
    assert not [s for s in result["foundation"]["services"] if s["upstream"]["port"] == 8080]


def test_mission1_security_invariants_are_not_regressed():
    result = validator.validate_foundation(root=ROOT)
    foundation = result["foundation"]
    rules = foundation["boundaryRules"]
    assert rules["directProviderRoutesAllowed"] is False and rules["fallbackRoutesAllowed"] is False
    assert rules["adminPubliclyReachable"] is False and rules["clientSuppliedIdentityHeadersTrusted"] is False
    assert rules["middlewareListenerSplit"]["canonicalPublicApiListener"] == 8095
    for entry in foundation["routes"]:
        if entry["lifecycle"] == "CANONICAL":
            route = result["materialized"][entry["routeId"]]
            assert route.methods and route.hosts and route.paths
            assert not {"DIRECT_PROVIDER_UPSTREAM", "HARD_CODED_UPSTREAM_IP", "NO_GATEWAY_AUTHENTICATION"} & set(entry["acceptedFindings"])
    assert foundation["pluginGovernance"]["globalPluginsAllowed"] == ["prometheus"]


# --------------------------------------------------------------------------- negative mutations


def test_unclassified_route_fails(repo):
    policy = read_json(repo, POLICY)
    policy["routes"] = [r for r in policy["routes"] if r["routeId"] != "control-plane-health"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "disagree on the route set")
    policy = read_json(BASE["root"], POLICY)
    del policy_entry(policy, "control-plane-health")["accessClass"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "lacks accessClass")


def test_protected_route_without_authentication_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["services"][0]["plugins"] = [p for p in document["services"][0]["plugins"] if p["name"] != "openid-connect"]
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "NO_GATEWAY_AUTHENTICATION|CLAIM_GUARD_WITHOUT_TOKEN_AUTHENTICATION")


def test_public_route_not_allowlisted_fails(repo):
    policy = read_json(repo, POLICY)
    policy["publicAllowlist"] = [i for i in policy["publicAllowlist"] if i["routeId"] != "codestra-token-validation-certification"]
    write_json(repo, POLICY, policy)
    expect_failure(repo, "public route codestra-token-validation-certification is not on the public allowlist")


def test_route_cannot_be_reclassified_public_by_policy_alone(repo):
    policy = read_json(repo, POLICY)
    entry = policy_entry(policy, "codestra-callback-read")
    entry["accessClass"] = "PUBLIC"
    entry["authenticationProfile"] = "PUBLIC_V1"
    policy["publicAllowlist"].append({"routeId": "codestra-callback-read", "reason": "not acceptable"})
    write_json(repo, POLICY, policy)
    expect_failure(repo, "class PUBLIC != foundation SERVICE_AUTHENTICATED")


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(issuer="https://auth-staging.codestra.co/realms/codestra"), "does not match the environment issuer"),
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(issuer="https://*.codestra.co/realms/codestra"), "does not match the environment issuer|wildcards are forbidden"),
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(algorithms=["RS256", "HS256"]), "RS256 only"),
    (lambda p: p["issuerProfiles"]["KEYCLOAK_CODESTRA_PRODUCTION"].update(clockSkewSeconds=600), "clock skew is unbounded"),
    (lambda p: p["audienceProfiles"]["MIDDLEWARE_API"].update(audience="*"), "must not be a wildcard"),
    (lambda p: p["audienceProfiles"]["CALLBACK_API"].update(audience="codestra-callback-api-other"), "!= foundation audience"),
    (lambda p: p["audienceProfiles"]["MONEYBEE_API"].update(clientIdIsAudience=True), "without a contract"),
    (lambda p: p["tokenCachePolicies"]["OIDC_CACHE_V1"].update(cacheTokensSalt="deadbeefcafefeed"), "through the vault"),
    (lambda p: p["tokenCachePolicies"]["OIDC_CACHE_V1"].update(cacheTtlSeconds=86400), "ttl is unbounded"),
    (lambda p: p["rules"].update(wildcardAudienceAllowed=True), "must remain forbidden"),
    (lambda p: p["rules"].update(identityHeaderAuthorityAllowed=True), "must remain forbidden"),
    (lambda p: p["failurePolicies"]["FAIL_CLOSED_V1"].update(downgradeToPublic=True), "allows downgrade to public"),
])
def test_profile_catalogue_mutations_fail(repo, mutate, match):
    profiles = read_json(repo, PROFILES)
    mutate(profiles)
    write_json(repo, PROFILES, profiles)
    expect_failure(repo, match)


@pytest.mark.parametrize(("route_id", "mutate", "match"), [
    ("codestra-n8n-command-submit", lambda e: e.update(issuerProfile="KEYCLOAK_CODESTRA_STAGING"), "is not the production realm"),
    ("codestra-n8n-command-submit", lambda e: e.update(issuerProfile="NONE"), "unknown issuer profile|is not the production realm"),
    ("codestra-n8n-command-submit", lambda e: e.update(audienceProfile="NONE"), "!= foundation audience"),
    ("codestra-n8n-command-submit", lambda e: e.update(audienceProfile="CALLBACK_API"), "!= foundation audience"),
    ("codestra-n8n-command-submit", lambda e: e.update(requiredScopes=[]), "required scopes drift"),
    ("codestra-n8n-command-submit", lambda e: e.update(requiredScopes=["middleware.*"]), "required scopes drift|wildcard scope"),
    ("codestra-n8n-command-submit", lambda e: e.update(authorizedParties=[]), "must not be empty"),
    ("codestra-n8n-command-submit", lambda e: e.update(authorizedParties=["someone-else"]), "is not an authorized party"),
    ("codestra-n8n-command-submit", lambda e: e.update(principalClasses=["HUMAN"]), "principal classes outside the profile"),
    ("codestra-n8n-command-submit", lambda e: e.update(authenticationProfile="HUMAN_OIDC_V1"), "does not serve class SERVICE_AUTHENTICATED"),
    ("codestra-n8n-command-submit", lambda e: e.update(authenticationProfile="LEGACY_SHARED_KEY_V1"), "does not serve class|is not part of profile|not allowed for lifecycle"),
    ("codestra-n8n-command-submit", lambda e: e.update(authenticationProfile="BLOCKED_NONE_V1"), "is not part of profile|not allowed for activation"),
    ("codestra-n8n-command-submit", lambda e: e.update(tenantPolicy="HEADER_AUTHORITY"), "unknown tenant policy"),
    ("codestra-n8n-command-submit", lambda e: e.update(identityPropagation="GATEWAY_MINTED_TENANT_ROLE"), "finding claims unstripped headers but the profile strips them"),
    ("codestra-n8n-command-submit", lambda e: e.update(acceptedFindings=[]), "forwards client identity headers without accepting the finding"),
    ("control-plane-system-admin", lambda e: e.update(principalClasses=["SERVICE"]), "principal classes outside the profile"),
    ("control-plane-system-admin", lambda e: e.update(authenticationProfile="SERVICE_OIDC_V1"), "does not serve class ADMIN_INTERNAL"),
    ("moneybee-account-bootstrap", lambda e: e.update(accessClass="SERVICE_AUTHENTICATED"), "class SERVICE_AUTHENTICATED != foundation AUTHENTICATED"),
    ("codestra-calling-command-submit", lambda e: e.update(principalClasses=["HUMAN"]), "principal classes outside the profile"),
])
def test_route_policy_mutations_fail(repo, route_id, mutate, match):
    policy = read_json(repo, POLICY)
    mutate(policy_entry(policy, route_id))
    write_json(repo, POLICY, policy)
    expect_failure(repo, match)


def test_authentication_downgrade_in_the_foundation_is_caught(repo):
    foundation = read_json(repo, FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "codestra-n8n-command-read")
    entry["authentication"] = "AUTHENTICATED"
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "class SERVICE_AUTHENTICATED != foundation AUTHENTICATED")
    foundation = read_json(BASE["root"], FOUNDATION)
    entry = next(r for r in foundation["routes"] if r["routeId"] == "codestra-n8n-command-read")
    entry["audience"] = None
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "requires an audience|source audience")


def test_wrong_issuer_in_a_source_fails(repo):
    path = "config/kong-n8n-control-plane-routes.json"
    contract = read_json(repo, path)
    contract["issuer"] = "https://auth.evil.example/realms/codestra"
    write_json(repo, path, contract)
    expect_failure(repo, "binds issuer https://auth.evil.example")


def test_global_authentication_plugin_fails(repo):
    document = read_yaml(repo, CONTROL_PLANE)
    document["plugins"].append({"name": "jwt", "config": {"claims_to_verify": ["exp"]}})
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, "not allowed globally|must never be global")


def test_plaintext_secret_in_any_authority_file_fails(repo):
    # Values are assembled at runtime so this test file never contains them.
    planted = "".join(chr(65 + i % 26) for i in range(40))
    key_name = "client_" + "secret"
    (repo / "operations/kong-database/notes.env").write_text(key_name + ": " + planted + "\n", encoding="utf-8")
    expect_failure(repo, "committed secret material detected.*client_secret_literal")
    (repo / "operations/kong-database/notes.env").unlink()
    pem = "-----BEGIN " + "PRIVATE KEY-----" + "\nMIIE\n" + "-----END " + "PRIVATE KEY-----" + "\n"
    (repo / "deploy/kong/leak.pem").write_text(pem, encoding="utf-8")
    expect_failure(repo, "private_key_block")


@pytest.mark.parametrize(("mutate", "match"), [
    (lambda c: c.update(cache_tokens_salt="synthetic-salt-value"), "cache_tokens_salt through the vault"),
    (lambda c: c.update(leeway=900), "leeway exceeds the bound"),
    (lambda c: c.update(cache_ttl=86400), "cache_ttl exceeds the bound"),
    (lambda c: c.update(anonymous="00000000-0000-0000-0000-000000000000"), "anonymous consumer"),
    (lambda c: c.update(audience=["*"]), "non-wildcard audience|source audience"),
    (lambda c: c.update(auth_methods=["bearer", "password"]), "only bearer authentication"),
])
def test_unsafe_openid_connect_settings_fail(repo, mutate, match):
    document = read_yaml(repo, CONTROL_PLANE)
    oidc = next(p for p in document["services"][0]["plugins"] if p["name"] == "openid-connect")
    mutate(oidc["config"])
    write_yaml(repo, CONTROL_PLANE, document)
    expect_failure(repo, match)


def test_ungoverned_log_plugin_requires_redaction(repo):
    foundation = read_json(repo, FOUNDATION)
    foundation["plugins"].append({
        "plugin": "http-log", "kind": "bundled", "authentication": False, "priority": 12, "allowedScopes": ["ROUTE"],
        "owner": "x", "purpose": "x", "securityImpact": "HIGH", "orderingDependency": "x", "environments": ["production"],
        "configurationSources": ["deploy/kong/control-plane.yml"],
    })
    write_json(repo, FOUNDATION, foundation)
    expect_failure(repo, "governed without credential redaction")
