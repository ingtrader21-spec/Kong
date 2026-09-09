import copy
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
from scripts.gateway_integrations import (AUTHORITY, ROOT, ContractError, canonical,
    compile_integrations, digest, load_json, validate, validate_set)
from tools.kongctl import package_release, verify_package


@pytest.fixture
def contract():
    return load_json(AUTHORITY / "examples/moneybee-account-bootstrap.json")


def compiled(contract):
    return compile_integrations([contract], environment="staging")


def test_example_compiles_to_guarded_upstream(contract):
    output = compiled(contract)
    service = output["kong"]["services"][0]
    route = service["routes"][0]
    plugins = {p["name"]: p["config"] for p in route["plugins"]}
    assert output["runtime_certified"] is False
    assert output["runtime_apply_authorized"] is False
    assert route["paths"] == ["~^/api/v2/account/bootstrap$"]
    assert route["protocols"] == ["https"]
    assert route["methods"] == ["OPTIONS", "POST"]
    assert service["tls_verify"] is True
    assert service["retries"] == 0
    assert plugins["openid-connect"]["auth_methods"] == ["bearer"]
    assert plugins["openid-connect"]["bearer_token_param_type"] == ["header"]
    assert plugins["codestra-authz"]["scopes"] == ["moneybee.account.bootstrap"]
    assert plugins["rate-limiting"]["fault_tolerant"] is False
    assert output["config_sha256"] == digest(output["kong"])
    assert all(row["runtime_result"] == "NOT_RUN" for row in output["test_matrix"])


@pytest.mark.parametrize("template", ["public-oidc-api", "internal-service-jwt", "private-mtls-api",
    "signed-webhook", "websocket-api", "public-health", "legacy-api-key"])
def test_every_policy_template_compiles(contract, template):
    spec = contract["spec"]
    auth, route = spec["authentication"], spec["routes"][0]
    auth["template"] = template
    if template in {"internal-service-jwt", "private-mtls-api"}:
        spec["exposure"] = "private"
        spec["policies"]["sourceAllowlist"] = ["10.20.0.0/24"]
    if template == "private-mtls-api":
        auth["caCertificateIds"] = ["12345678-1234-1234-1234-123456789abc"]
    if template in {"signed-webhook", "public-health", "legacy-api-key"}:
        spec["authentication"] = {"template": template}
        route["scopes"] = []
    if template == "signed-webhook":
        spec["authentication"].update(secretRef="{vault://env/webhook-key}", keyId="webhook-v1")
        spec["policies"]["corsOrigins"] = []
    if template == "legacy-api-key":
        spec["authentication"]["legacySunset"] = "2099-01-01"
    if template == "websocket-api":
        route["methods"] = ["GET"]
    if template == "public-health":
        route.update(path="/healthz", methods=["GET"])
        contract["metadata"]["dataClassification"] = "public"
    assert compiled(contract)["kong"]["services"]


@pytest.mark.parametrize("section,key,value,code", [
    ("upstream", "dnsName", "api.external-provider.com", "upstream_not_registered"),
    ("upstream", "dnsName", "127.0.0.1", "literal_address_not_allowed"),
    ("upstream", "dnsName", "middleware--1.internal.codestra", "upstream_not_registered"),
    ("upstream", "tlsServerName", "attacker.example", "upstream_sni_mismatch"),
    ("policies", "sourceAllowlist", ["0.0.0.0/0"], "unbounded_source_network"),
    ("policies", "sourceAllowlist", ["10.0.0.1/24"], "invalid_source_network"),
    ("policies", "corsOrigins", ["https://example.com@attacker.example"], "invalid_cors_origin"),
    ("policies", "corsOrigins", ["https://example.com/path"], "invalid_cors_origin"),
    ("policies", "corsOrigins", ["https://*.example.com"], "invalid_cors_origin"),
    ("policies", "redisHost", "redis.attacker.example", "redis_not_registered"),
    ("authentication", "scopes", ["unregistered.scope"], "unknown_scope"),
    ("authentication", "secretRef", "do-not-echo-me", "integration_schema_invalid"),
    ("release", "runtimeApplyAuthorized", True, "integration_schema_invalid"),
])
def test_invalid_policy_rejected_without_value_disclosure(contract, section, key, value, code):
    contract["spec"][section][key] = value
    with pytest.raises(ContractError, match=code) as exc:
        compiled(contract)
    assert "do-not-echo-me" not in str(exc.value)


@pytest.mark.parametrize("path", ["/a/../b", "/a//b", "/a/{x}/{x}", "/a/{x-tail}", "/a/{x}tail", "/a?b"])
def test_bad_paths_rejected(contract, path):
    contract["spec"]["routes"][0]["path"] = path
    with pytest.raises(ContractError):
        compiled(contract)


@pytest.mark.parametrize("left,right,match,collides", [
    ("/orders", "/orders", "exact", True),
    ("/orders/{id}", "/orders/current", "exact", True),
    ("/orders", "/orders/current", "prefix", True),
    ("/orders", "/orders-admin", "prefix", False),
    ("/orders", "/orders/current", "exact", False),
    ("/", "/orders", "prefix", True),
])
def test_route_collision_semantics(contract, left, right, match, collides):
    second = copy.deepcopy(contract)
    second["metadata"]["id"] = "second-integration"
    contract["spec"]["routes"][0].update(path=left, match=match)
    second["spec"]["routes"][0].update(path=right, operationIds=["second-operation"])
    if collides:
        with pytest.raises(ContractError, match="ambiguous_route_collision"):
            validate_set([contract, second])
    else:
        forward = compile_integrations([contract, second], environment="staging")
        reverse = compile_integrations([second, contract], environment="staging")
        assert canonical(forward) == canonical(reverse)


def test_method_and_environment_namespaces(contract):
    second = copy.deepcopy(contract)
    second["metadata"].update(id="second-integration", environment="production")
    validate_set([contract, second])
    second["metadata"]["environment"] = "staging"
    contract["spec"]["policies"]["corsOrigins"] = []
    second["spec"]["policies"]["corsOrigins"] = []
    second["spec"]["routes"][0].update(methods=["GET"], operationIds=["get-account"])
    validate_set([contract, second])


def test_implicit_cors_preflight_collisions_are_rejected(contract):
    other = copy.deepcopy(contract)
    other["metadata"]["id"] = "other-integration"
    other["spec"]["routes"][0].update(methods=["GET"], operationIds=["get-account"])
    with pytest.raises(ContractError, match="ambiguous_route_collision"):
        validate_set([contract, other])


def test_openapi_keeps_different_host_operations(contract):
    other = copy.deepcopy(contract)
    other["metadata"]["id"] = "other-integration"
    other["spec"]["host"] = "other.codestra.example"
    other["spec"]["routes"][0]["operationIds"] = ["other-operation"]
    docs = compile_integrations([contract, other], environment="staging")["openapi_stub"]
    assert len(docs) == 2
    assert {d["paths"]["/api/v2/account/bootstrap"]["post"]["operationId"] for d in docs} == {"bootstrap-account", "other-operation"}


def test_conflicting_shared_service_rejected(contract):
    second = copy.deepcopy(contract)
    second["metadata"]["id"] = "second-integration"
    second["spec"]["upstream"]["port"] = 8443
    with pytest.raises(ContractError, match="conflicting_service_binding"):
        validate_set([contract, second])


def test_write_retry_and_auth_fields_fail_closed(contract):
    contract["spec"]["upstream"].update(retries=1, idempotencyAuthority="none")
    with pytest.raises(ContractError, match="unsafe_write_retry"):
        validate(contract)
    contract["spec"]["upstream"]["retries"] = 0
    contract["spec"]["authentication"] = {"template": "legacy-api-key"}
    with pytest.raises(ContractError, match="authentication_fields_mismatch"):
        validate(contract)


@pytest.mark.parametrize("raw", ['{"key":1,"key":2}', '{"key":NaN}', '[', '"' + 'x' * 1_048_576 + '"'])
def test_bounded_unambiguous_json(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_text(raw)
    with pytest.raises(ContractError):
        load_json(path)


def test_package_determinism_integrity_and_no_certification(contract, tmp_path):
    output = compiled(contract)
    paths = [tmp_path / "a.zip", tmp_path / "b.zip"]
    for path in paths:
        package_release(output, path, "a" * 40, "sha256:" + "b" * 64, "c" * 40)
    assert paths[0].read_bytes() == paths[1].read_bytes()
    assert verify_package(paths[0])["runtime_certified"] is False
    with zipfile.ZipFile(paths[0]) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    files["kong.json"] = b'{}\n'
    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered, "w") as archive:
        for name, data in files.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    with pytest.raises(ContractError, match="package_integrity_mismatch"):
        verify_package(tampered)


def test_cli_validates_and_refuses_overwrite(tmp_path):
    cli = [sys.executable, str(ROOT / "tools/kongctl.py")]
    result = subprocess.run(cli + ["integration", "validate", str(AUTHORITY / "examples/moneybee-account-bootstrap.json")],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["runtime_certified"] is False
    target = tmp_path / "integration.json"
    args = cli + ["integration", "init", "--id", "example-id", "--owner", "platform-team",
                  "--security-owner", "security-team", "--output", str(target)]
    assert subprocess.run(args, capture_output=True).returncode == 0
    bundle = tmp_path / "integration.json.onboarding"
    assert {path.name for path in bundle.iterdir()} == {"test-matrix.json", "openapi-stub.json", "rollback-plan.json", "runbook.md"}
    assert load_json(bundle / "rollback-plan.json")["previous_signed_release"] is None
    before = target.read_bytes()
    assert subprocess.run(args, capture_output=True).returncode == 2
    assert target.read_bytes() == before
