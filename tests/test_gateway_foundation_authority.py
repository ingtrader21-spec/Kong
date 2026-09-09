from pathlib import Path

import pytest
import yaml
from openapi_spec_validator import validate as validate_openapi

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return yaml.safe_load((ROOT / path).read_text())


def test_complete_control_openapi_is_valid_and_rejects_raw_admin_payloads():
    document = read("deploy/gateway-control-api/openapi.yaml")
    validate_openapi(document)
    paths = document["paths"]
    assert set(paths["/v1/integrations"]) == {"post", "get"}
    assert set(paths["/v1/integrations/{integration_id}"]) == {"get", "patch"}
    for suffix in ("validate", "preview", "submit", "approve", "deployments", "credentials/rotate", "certificates/rotate", "deprecate"):
        assert "post" in paths["/v1/integrations/{integration_id}/" + suffix]
    for suffix in ("status", "drift", "metrics"):
        assert "get" in paths["/v1/integrations/{integration_id}/" + suffix]
    for path in ("/v1/deployments/{deployment_id}", "/v1/templates", "/v1/policies", "/v1/audit-events",
                 "/healthz", "/readyz", "/version", "/metrics"):
        assert "get" in paths[path]
    assert "post" in paths["/v1/deployments/{deployment_id}/rollback"]
    schemas = document["components"]["schemas"]
    assert schemas["DeploymentCommand"]["additionalProperties"] is False
    assert set(schemas["DeploymentCommand"]["properties"]) == {"environment", "approval_id", "release"}
    assert schemas["ReleaseIdentity"]["additionalProperties"] is False
    for path, methods in paths.items():
        for method, operation in methods.items():
            if method in {"post", "patch"}:
                assert any(p["name"] == "Idempotency-Key" and p["required"] for p in operation["parameters"])
                assert operation["security"]
    assert paths["/v1/integrations/{integration_id}/approve"]["post"]["security"] != paths["/v1/integrations/{integration_id}/deployments"]["post"]["security"]


@pytest.mark.parametrize("topology", ["hybrid", "traditional"])
def test_topology_is_private_bounded_and_nonactivated(topology):
    document = read(f"deploy/gateway-platform/compose.{topology}.yaml")
    for service in document["services"].values():
        assert not service.get("ports")
        assert not service.get("privileged")
        assert not service.get("network_mode")
        assert service["read_only"] is True
        assert service["user"] == "1000:1000"
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert service["pids_limit"] <= 256
        assert service["mem_limit"] and service["cpus"]
        assert service["profiles"] == [topology + "-source"]
        assert "@${KONG_PLATFORM_IMAGE_DIGEST:?" in service["image"]
        assert "docker.sock" not in str(service)
        assert service["environment"]["KONG_LICENSE_PATH"] == "/run/secrets/kong_license"
        assert "kong_license" in service["secrets"]
        assert "oidc_cache_tokens_salt" in service["secrets"]
        webhook_mounts = [mount for mount in service.get("volumes", [])
                          if isinstance(mount, dict) and mount.get("target") == "/run/secrets/webhooks"]
        assert webhook_mounts == [{
            "type": "bind",
            "source": "${GATEWAY_WEBHOOK_SECRET_DIRECTORY:?approved per-integration webhook secret directory required}",
            "target": "/run/secrets/webhooks",
            "read_only": True,
        }]
        assert service["environment"]["KONG_STATUS_LISTEN"] == "0.0.0.0:8100"
        assert service["environment"]["KONG_VAULTS"] == "env"
        if service["environment"]["KONG_PROXY_LISTEN"] != "off":
            assert service["environment"]["KONG_TRUSTED_IPS"].startswith("${KONG_TRUSTED_IPS:?")
            assert service["environment"]["KONG_REAL_IP_HEADER"] == "X-Forwarded-For"
            assert service["environment"]["KONG_REAL_IP_RECURSIVE"] == "on"
    assert len({s["image"] for s in document["services"].values()}) == 1
    wrapper = (ROOT / "deploy/gateway-platform/codestra-kong-entrypoint.sh").read_text()
    assert "export KONG_OIDC_CACHE_TOKENS_SALT" in wrapper
    assert "/run/secrets/oidc_cache_tokens_salt" in wrapper
    assert "/run/secrets/webhooks" in wrapper
    assert '[ ! -r "$sx_webhook_secret_directory" ]' in wrapper
    assert '[ ! -x "$sx_webhook_secret_directory" ]' in wrapper
    assert 'sx_webhook_secret_count=$((sx_webhook_secret_count + 1))' in wrapper
    assert '[ "$sx_webhook_secret_count" -eq 0 ]' in wrapper
    assert "^kong-webhook-[a-z][a-z0-9-]{1,96}$" in wrapper
    assert '"${#sx_webhook_secret_value}" -lt 32' in wrapper
    boundary = read("deploy/gateway-platform/network-boundaries.yaml")
    for name, network in document["networks"].items():
        assert network["name"] == boundary["networks"][name]["docker_name"]
        assert boundary["networks"][name]["internal_required"] is True


def test_hybrid_dp_has_no_database_authority_and_retains_cache():
    document = read("deploy/gateway-platform/compose.hybrid.yaml")
    for name in ("kong-dp-1", "kong-dp-2"):
        service = document["services"][name]
        assert "kong_database" not in service["networks"]
        assert "kong_runtime_password" not in service["secrets"]
        assert not any(key.startswith("KONG_PG_") for key in service["environment"])
        assert service["environment"]["KONG_DATABASE"] == "off"
        assert service["environment"]["KONG_ADMIN_LISTEN"] == "off"
        assert service["environment"]["KONG_CLUSTER_MTLS"] == "pki"
        assert service["volumes"]
    assert document["services"]["kong-cp"]["environment"]["KONG_PROXY_LISTEN"] == "off"


def test_traditional_admin_is_management_only():
    document = read("deploy/gateway-platform/compose.traditional.yaml")
    for name in ("kong-proxy-1", "kong-proxy-2"):
        assert document["services"][name]["environment"]["KONG_ADMIN_LISTEN"] == "off"
        assert "kong_admin" not in document["services"][name]["networks"]
    management = document["services"]["kong-management"]
    assert management["environment"]["KONG_ADMIN_LISTEN"] == "127.0.0.1:8001"
    assert management["environment"]["KONG_PROXY_LISTEN"] == "off"
    assert "kong_proxy" not in management["networks"]
