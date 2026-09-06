from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_global_prometheus_plugin_is_cardinality_safe() -> None:
    config = yaml.safe_load((ROOT / "deploy/kong/control-plane.yml").read_text())
    plugins = [plugin for plugin in config.get("plugins", []) if plugin.get("name") == "prometheus"]
    assert len(plugins) == 1
    assert plugins[0].get("enabled", True) is True
    plugin_config = plugins[0]["config"]
    assert plugin_config == {
        "status_code_metrics": True,
        "latency_metrics": True,
        "bandwidth_metrics": True,
        "upstream_health_metrics": True,
        "ai_metrics": False,
        "per_consumer": False,
    }


def test_metrics_are_not_exposed_as_a_proxy_route() -> None:
    config = yaml.safe_load((ROOT / "deploy/kong/control-plane.yml").read_text())
    for service in config.get("services", []):
        for route in service.get("routes", []):
            paths = route.get("paths", [])
            assert "/metrics" not in paths
            assert "/status" not in paths


def test_status_api_contract_is_private_network_only() -> None:
    values = {}
    for raw_line in (ROOT / "deploy/kong/observability.env.example").read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    assert values == {
        "KONG_STATUS_LISTEN": "0.0.0.0:8100",
        "KONG_STATUS_ACCESS_LOG": "off",
        "KONG_STATUS_ERROR_LOG": "stderr",
        "CODESTRA_OBSERVABILITY_NETWORK": "codestra-observability",
        "CODESTRA_OBSERVABILITY_ALIAS": "kong",
    }
    assert "KONG_ADMIN_LISTEN" not in values
