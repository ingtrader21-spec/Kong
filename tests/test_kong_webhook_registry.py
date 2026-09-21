from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_kong_webhook_registry.py"
SPEC = importlib.util.spec_from_file_location("kong_webhook_registry", MODULE_PATH)
assert SPEC and SPEC.loader
webhooks = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = webhooks
SPEC.loader.exec_module(webhooks)

REGISTRY = webhooks.load_json(ROOT / "config" / "kong-webhook-registry.v1.json")


def test_registry_is_transport_only_and_fail_closed() -> None:
    webhooks.validate_registry_shape(REGISTRY)
    assert REGISTRY["runtime_apply_authorized"] is False
    assert REGISTRY["provider_effects_enabled"] is False
    assert REGISTRY["invariants"]["direct_provider_routes"] == 0
    assert REGISTRY["invariants"]["direct_odoo_routes"] == 0
    assert REGISTRY["invariants"]["direct_n8n_execution_routes"] == 0


def test_canonical_ingress_is_middleware_only_with_zero_gateway_retries() -> None:
    entries = {row["id"]: row for row in REGISTRY["canonical_entries"]}
    assert set(entries) == {"odoo-events", "n8n-results", "github-events"}
    for row in entries.values():
        assert row["gateway"] == "Kong"
        assert row["upstream"] == "middleware-integration-api:8095"
        assert row["event_ledger_owner"] == "Middleware"
        assert row["gateway_retries"] == 0
        assert row["idempotency"]["required"] is True

    assert entries["odoo-events"]["idempotency"]["carrier"] == "body.event_id"
    assert entries["n8n-results"]["idempotency"]["carrier"] == "Idempotency-Key"
    assert entries["github-events"]["idempotency"]["carrier"] == "Idempotency-Key"


def test_pending_provider_ingress_stays_404_until_contract_exists() -> None:
    pending = {row["id"]: row for row in REGISTRY["pending_denied_entries"]}
    assert set(pending) == {
        "telnexa",
        "vicidial-call-result",
        "n8n-acknowledgements",
        "observability-incidents",
        "observability-kpis",
        "sms-inbound",
    }
    for row in pending.values():
        assert row["classification"] == "DENIED_PENDING_CONTRACT"
        assert row["expected_public_status"] == 404


def test_registry_does_not_claim_business_or_durable_event_authority() -> None:
    denied_ownership = set(REGISTRY["invariants"]["gateway_does_not_own"])
    assert "business authorization" in denied_ownership
    assert "provider-event durable ledger" in denied_ownership
    assert "replay state" in denied_ownership
    assert "business database writes" in denied_ownership
    assert "provider retry/reconciliation" in denied_ownership
