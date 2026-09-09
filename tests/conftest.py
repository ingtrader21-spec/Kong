import json
from pathlib import Path
import hashlib
from datetime import datetime, timedelta, timezone
import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def synthetic_certification():
    """Synthetic observations for negative tests, never publishable runtime proof."""
    from tools import kong_certification as c
    from tools.verify_staging_certification import certification_id, RECEIPT_SCHEMA, WORKFLOW, REPOSITORY

    def build(candidate_raw, inventory_raw, now=None):
        now = now or datetime.now(timezone.utc)
        candidate, inventory = json.loads(candidate_raw), json.loads(inventory_raw)
        observation = {"passed": True, "observation_sha256": "1" * 64}
        document = {
            "schema": c.SCHEMA, "environment": "isolated-staging",
            "candidate": {key: candidate[key] for key in c.CANDIDATE_FIELDS},
            "candidate_manifest_sha256": hashlib.sha256(candidate_raw).hexdigest(),
            "route_inventory_sha256": hashlib.sha256(inventory_raw).hexdigest(),
            "started_at": (now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
            "completed_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
            "route_checks": {name: {key: dict(observation) for key in required}
                             for name, required in c.contract_matrix(inventory).items()},
            "global_checks": {key: dict(observation) for key in c.GLOBAL_CHECKS},
            "effects_before": dict.fromkeys(c.EFFECTS, 0), "effects_after": dict.fromkeys(c.EFFECTS, 0),
            "rollback": {"source_sha": candidate["rollback_source_sha"], "candidate_run_id": 321, "image_digest": "sha256:" + "2" * 64,
                         "config_sha256": "3" * 64, "backup_sha256": "4" * 64,
                         "restore_observation_sha256": "5" * 64},
            "canary": {"methods": ["GET", "HEAD"], "traffic_basis_points": 100, "observed_requests": 10},
            "secrets_captured": False, "public_traffic_percent": 0,
        }
        raw = (json.dumps(document, sort_keys=True) + "\n").encode()
        rollback_raw = json.dumps({"source_sha": candidate["rollback_source_sha"],
            "kong_image_digest": "sha256:" + "2" * 64, "kong_declarative_config_sha256": "3" * 64}, sort_keys=True)
        receipt = {"schema": RECEIPT_SCHEMA, "repository": REPOSITORY, "workflow": WORKFLOW,
                   "source_sha": candidate["source_sha"], "staging_sha": "b" * 40, "run_id": 123,
                   "run_attempt": 1, "artifact_id": 42, "artifact_digest": "sha256:" + "6" * 64,
                   "certification_sha256": hashlib.sha256(raw).hexdigest(),
                   "certification_id": certification_id(candidate["source_sha"], 123, 42),
                   "rollback_manifest_json": rollback_raw,
                   "rollback_artifact": {"source_sha": candidate["rollback_source_sha"], "run_id": 321,
                       "artifact_id": 43, "artifact_digest": "sha256:" + "7" * 64,
                       "manifest_sha256": hashlib.sha256(rollback_raw.encode()).hexdigest()}}
        return raw, receipt
    return build


def pytest_sessionstart(session):
    contract_path = ROOT / "config/kong-moneybee-identity-routes.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))

    assert contract["state"] == "desired-not-activated"
    assert contract["canonicalHost"] == "api.moneybeeloan.com"

    identity = contract["identity"]
    assert identity["issuer"] == "https://auth.codestra.co/realms/codestra"
    assert identity["requiredAudience"] == "moneybee-api"
    assert identity["registrationClient"] == "moneybee-borrower"

    route = contract["routes"][0]
    assert route["path"] == "/api/v2/account/bootstrap"
    assert route["methods"] == ["POST"]
    assert route["allowedAuthorizedParties"] == ["moneybee-borrower"]
    assert route["emailVerifiedRequired"] is True
    assert route["backendMustRevalidateJwt"] is True
    assert route["rateLimitPerMinute"] <= 10
    assert route["maxBodyBytes"] <= 65536

    security = contract["security"]
    assert security["tlsRequired"] is True
    assert security["wildcardHostsAllowed"] is False
    assert security["browserPasswordTransit"] is False
    assert security["otpTransit"] is False
    assert security["keycloakAdminApiExposure"] is False
    assert security["activationRequiresReviewedRuntimeChange"] is True
