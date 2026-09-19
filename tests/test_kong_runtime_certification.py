"""Synthetic offline fixtures: these tests establish no live certification."""
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

from tools import kong_certification as c
from tools import verify_staging_certification as verifier
from tools.release_contract import STANDBY_IMAGE
from tools import package_staging_certification as publisher
from scripts import run_kong_standby_acceptance as acceptance


@pytest.fixture
def bundle(synthetic_certification):
    candidate = {"source_sha":"a"*40, "source_tree":"b"*40,
                 "kong_image_digest":"sha256:"+"c"*64, "standby_auth_image_digest":"sha256:"+"d"*64,
                 "kong_declarative_config_sha256":"e"*64, "rollback_source_sha":"f"*40}
    inventory = {"schema":"codestra.kong.production-route-inventory.v2", "expectedRouteCount":2,
                 "routes":[{"name":"jwt-route","plugins":["openid-connect"]},
                           {"name":"key-route","plugins":["key-auth"]}]}
    candidate_raw, inventory_raw = json.dumps(candidate).encode(), json.dumps(inventory).encode()
    now = datetime.now(timezone.utc)
    raw, receipt = synthetic_certification(candidate_raw, inventory_raw, now)
    return raw, receipt, candidate_raw, inventory_raw, now


def test_complete_synthetic_report_is_validated_without_executing_anything(bundle):
    raw, receipt, candidate, inventory, now = bundle
    document = verifier.validate_receipt(receipt, raw, candidate, inventory, now=now)
    assert set(document["route_checks"]["jwt-route"]) == set(c.ROUTE_CHECKS + c.JWT_CHECKS)
    assert set(document["route_checks"]["key-route"]) == set(c.ROUTE_CHECKS)


@pytest.mark.parametrize("damage", [
    "missing-route", "extra-route", "missing-case", "failed-case", "truthy-case", "missing-global",
    "observation-hash", "wrong-source", "wrong-image", "candidate-hash", "inventory-hash",
    "rollback-source", "rollback-digest", "restore-hash", "missing-counter", "counter-increment",
    "counter-reset", "bool-counter", "future", "stale", "reversed-time", "naive-time",
    "production", "secret-field", "secrets-captured", "public-traffic", "canary-write",
    "canary-too-large", "canary-empty", "unknown-check-field",
])
def test_partial_or_unsafe_runtime_claims_fail_closed(bundle, damage):
    raw, receipt, candidate, inventory, now = bundle
    doc = json.loads(raw)
    if damage == "missing-route": del doc["route_checks"]["key-route"]
    elif damage == "extra-route": doc["route_checks"]["unknown"] = {}
    elif damage == "missing-case": del doc["route_checks"]["jwt-route"]["wrong_tenant"]
    elif damage == "failed-case": doc["route_checks"]["jwt-route"]["wrong_issuer"]["passed"] = False
    elif damage == "truthy-case": doc["global_checks"]["backup_restore"]["passed"] = 1
    elif damage == "missing-global": del doc["global_checks"]["private_admin_peer_denial"]
    elif damage == "observation-hash": doc["global_checks"]["backup_restore"]["observation_sha256"] = "PENDING"
    elif damage == "wrong-source": doc["candidate"]["source_sha"] = "0"*40
    elif damage == "wrong-image": doc["candidate"]["kong_image_digest"] = "sha256:"+"0"*64
    elif damage == "candidate-hash": doc["candidate_manifest_sha256"] = "0"*64
    elif damage == "inventory-hash": doc["route_inventory_sha256"] = "0"*64
    elif damage == "rollback-source": doc["rollback"]["source_sha"] = "0"*40
    elif damage == "rollback-digest": doc["rollback"]["image_digest"] = "latest"
    elif damage == "restore-hash": del doc["rollback"]["restore_observation_sha256"]
    elif damage == "missing-counter": del doc["effects_after"]["calls"]
    elif damage == "counter-increment": doc["effects_after"]["sms"] = 1
    elif damage == "counter-reset": doc["effects_before"]["emails"] = 1
    elif damage == "bool-counter": doc["effects_after"]["payments"] = False
    elif damage in {"future", "stale"}:
        shift = timedelta(days=2 if damage == "future" else -2)
        for field in ("started_at", "completed_at"):
            doc[field] = (c.timestamp(doc[field]) + shift).isoformat().replace("+00:00", "Z")
    elif damage == "reversed-time": doc["started_at"],doc["completed_at"] = doc["completed_at"],doc["started_at"]
    elif damage == "naive-time": doc["completed_at"] = doc["completed_at"][:-1]
    elif damage == "production": doc["environment"] = "production"
    elif damage == "secret-field": doc["authorization"] = "untrusted-value"
    elif damage == "secrets-captured": doc["secrets_captured"] = True
    elif damage == "public-traffic": doc["public_traffic_percent"] = 1
    elif damage == "canary-write": doc["canary"]["methods"] = ["POST"]
    elif damage == "canary-too-large": doc["canary"]["traffic_basis_points"] = 101
    elif damage == "canary-empty": doc["canary"]["observed_requests"] = 0
    elif damage == "unknown-check-field": doc["global_checks"]["pitr"]["response_body"] = "untrusted"
    with pytest.raises(ValueError): c.validate_bytes(json.dumps(doc).encode(),candidate,inventory,
        rollback_candidate=json.loads(receipt["rollback_manifest_json"]),now=now)


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}',b'{"number":NaN}',b'[]',b'x'*(c.MAX_DOCUMENT+1)])
def test_ambiguous_or_unbounded_json_rejected(raw):
    with pytest.raises(ValueError): c.decode(raw)


def run_fixture():
    return {"id":123,"head_sha":"b"*40,"head_branch":"staging","path":verifier.WORKFLOW,
            "event":"workflow_dispatch","status":"completed","conclusion":"success","run_attempt":1,
            "repository":{"full_name":verifier.REPOSITORY},"head_repository":{"full_name":verifier.REPOSITORY}}


@pytest.mark.parametrize("change", [{"id":124},{"head_branch":"main"},{"head_branch":"feature/x"},
    {"path":".github/workflows/staging-certification.yml"},{"event":"pull_request"},
    {"status":"in_progress"},{"conclusion":"failure"},{"run_attempt":True},
    {"repository":{"full_name":"foreign/repo"}}])
def test_only_completed_runtime_workflow_can_issue_receipt(bundle, change):
    candidate = json.loads(bundle[2]); run = run_fixture()
    commit = {"sha":"b"*40,"commit":{"verification":{"verified":True},"tree":{"sha":candidate["source_tree"]}}}
    verifier.validate_run(run,123,commit,candidate)
    run.update(change)
    with pytest.raises(ValueError): verifier.validate_run(run,123,commit,candidate)


@pytest.mark.parametrize("field,value", [("verification",{"verified":False}),("tree",{"sha":"0"*40})])
def test_signed_staging_tree_must_match_original_candidate(bundle,field,value):
    candidate = json.loads(bundle[2]); commit = {"sha":"b"*40,"commit":{"verification":{"verified":True},"tree":{"sha":"b"*40}}}
    commit["commit"][field] = value
    with pytest.raises(ValueError): verifier.validate_run(run_fixture(),123,commit,candidate)


def archive(raw, extra=None):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream,"w") as output:
        output.writestr("certification.json",raw)
        if extra: output.writestr(extra,b"untrusted")
    value = stream.getvalue()
    return value,{"id":42,"name":"kong-staging-certification-"+"a"*40+"-1","expired":False,
                  "digest":"sha256:"+hashlib.sha256(value).hexdigest(),"size_in_bytes":len(value),
                  "workflow_run":{"id":123,"head_sha":"b"*40}}


@pytest.mark.parametrize("damage", ["tamper","traversal","duplicate","old-attempt","expired","foreign-run","partial-list","too-large"])
def test_artifact_selection_and_bytes_are_bound_to_latest_run(bundle,damage):
    raw,receipt,candidate,inventory,now = bundle
    value,artifact = archive(raw,"../escape" if damage=="traversal" else "certification.json" if damage=="duplicate" else None)
    if damage == "tamper": value += b"tampered"
    elif damage == "old-attempt": artifact["name"] = artifact["name"][:-1]+"0"
    elif damage == "expired": artifact["expired"] = True
    elif damage == "foreign-run": artifact["workflow_run"]["id"] = 124
    elif damage == "too-large": artifact["size_in_bytes"] = 10*c.MAX_DOCUMENT
    with pytest.raises(ValueError):
        verifier.select_artifact({"total_count":2 if damage=="partial-list" else 1,"artifacts":[artifact]},run_fixture(),"a"*40)
        verifier.verified_document(value,artifact,candidate,inventory,
            rollback_candidate=json.loads(receipt["rollback_manifest_json"]),now=now)


def test_valid_artifact_preserves_original_bytes(bundle):
    raw,receipt,candidate,inventory,now=bundle; value,artifact=archive(raw)
    assert verifier.verified_document(value,artifact,candidate,inventory,
        rollback_candidate=json.loads(receipt["rollback_manifest_json"]),now=now)[0] == raw


def test_observation_packager_rejects_symlinks_and_unapproved_hash(tmp_path):
    path=tmp_path/"observation"; path.write_bytes(b"{}")
    link=tmp_path/"link"; link.symlink_to(path)
    with pytest.raises((OSError,ValueError)): publisher.read_observation(link,hashlib.sha256(b"{}").hexdigest())
    with pytest.raises(ValueError): publisher.read_observation(path,"PENDING")


def test_acceptance_default_does_not_read_credentials_or_issue_requests(monkeypatch):
    monkeypatch.setattr(sys,"argv",["acceptance"])
    monkeypatch.setattr(acceptance,"credentials",lambda:pytest.fail("credentials touched without execution"))
    assert acceptance.main()==2


def test_acceptance_does_not_echo_response_bodies(capsys):
    with pytest.raises(ValueError) as error: acceptance.expect("MISSING_TOKEN",401,(500,b"sensitive-response"))
    assert "sensitive-response" not in str(error.value) + capsys.readouterr().out


@pytest.mark.parametrize("value", [{"status":"accepted","external_action":True},{"status":"accepted_mock"},[],{}])
def test_acceptance_rejects_non_mock_success(value):
    with pytest.raises(ValueError): acceptance.expect("MOCK",200,(200,json.dumps(value).encode()))


def test_acceptance_denies_redirects_and_oversized_replies():
    with pytest.raises(ValueError): acceptance.NoRedirect().redirect_request(None,None,302,None,None,"https://foreign.invalid")
    class Reply:
        def read(self, limit):
            assert limit == acceptance.MAX_RESPONSE + 1
            return b"x"*limit
    with pytest.raises(ValueError): acceptance.read_response(Reply())


def test_workflow_consumes_authenticated_runtime_artifact():
    root=Path(__file__).resolve().parents[1]
    workflow=(root/".github/workflows/release.yml").read_text()
    assert "vars.STAGING_CERTIFICATION" not in workflow
    assert "tools/verify_staging_certification.py" in workflow and "--staging-receipt" in workflow
    publisher_workflow=(root/".github/workflows/runtime-certification.yml").read_text()
    assert "environment: staging" in publisher_workflow and "GITHUB_REF_PROTECTED" in publisher_workflow
    assert "OBSERVATION_SHA256" in publisher_workflow and "run_kong_standby_acceptance.py" not in publisher_workflow


def test_end_to_end_authenticated_receipt_and_release_inputs(bundle,tmp_path,monkeypatch):
    raw,receipt,candidate_raw,inventory_raw,now=bundle
    value,artifact=archive(raw); run=run_fixture()
    run["updated_at"]=now.isoformat().replace("+00:00","Z")
    commit={"sha":"b"*40,"commit":{"verification":{"verified":True},"tree":{"sha":"b"*40}}}
    replies={"actions/runs/123":json.dumps(run).encode(),"commits/"+"b"*40:json.dumps(commit).encode(),
             "actions/runs/123/artifacts?per_page=100":json.dumps({"total_count":1,"artifacts":[artifact]}).encode(),
             "actions/artifacts/42/zip":value}
    monkeypatch.setattr(verifier,"api",lambda path:replies[path])
    monkeypatch.setattr(verifier,"load_rollback_candidate", lambda source, run_id:
        (receipt["rollback_manifest_json"].encode(), receipt["rollback_artifact"]))
    candidate=tmp_path/"candidate.json"; candidate.write_bytes(candidate_raw)
    inventory=tmp_path/"inventory.json"; inventory.write_bytes(inventory_raw)
    output=tmp_path/"verified"; github_output=tmp_path/"job-output"
    monkeypatch.setattr(sys,"argv",["verify","--source-sha","a"*40,"--run-id","123",
        "--candidate-manifest",str(candidate),"--inventory",str(inventory),"--output-dir",str(output),
        "--github-output",str(github_output)])
    assert verifier.main()==0
    verified_receipt=json.loads((output/"receipt.json").read_text())
    assert verified_receipt["artifact_digest"]==artifact["digest"]
    assert (output/"certification.json").read_bytes()==raw
    assert github_output.read_text()=="staging_certification=PASS:"+"a"*40+":github-actions/123/42\n"
    verifier.validate_receipt(verified_receipt,raw,candidate_raw,inventory_raw,now=now)


def test_matrix_generation_is_deterministic_and_not_runtime_pass(tmp_path,monkeypatch):
    path=tmp_path/"plan.json"
    monkeypatch.setattr(sys,"argv",["plan","--output",str(path)])
    assert c.main()==0
    original=path.read_bytes()
    assert c.main()==0 and path.read_bytes()==original
    plan=json.loads(original)
    assert plan["runtime_certified"] is False and len(plan["route_checks"])==27


@pytest.mark.parametrize('field,value', [('image_digest','sha256:'+'9'*64),('config_sha256','9'*64)])
def test_syntactically_valid_wrong_rollback_identity_is_rejected(bundle,field,value):
    raw,receipt,candidate,inventory,now=bundle
    document=json.loads(raw); document['rollback'][field]=value
    with pytest.raises(ValueError,match='rollback_release_identity_mismatch'):
        c.validate_bytes(json.dumps(document).encode(),candidate,inventory,
            rollback_candidate=json.loads(receipt['rollback_manifest_json']),now=now)


def test_rollback_authority_is_mandatory_and_receipt_bound(bundle):
    raw,receipt,candidate,inventory,now=bundle
    with pytest.raises(ValueError,match='authenticated_rollback_candidate_required'):
        c.validate_bytes(raw,candidate,inventory,now=now)
    receipt['rollback_artifact']['run_id']=322
    with pytest.raises(ValueError,match='rollback_receipt_mismatch'):
        verifier.validate_receipt(receipt,raw,candidate,inventory,now=now)


@pytest.mark.parametrize('damage',[None,'unsigned','tree','source','failed-run','foreign-repository','tampered-archive'])
def test_rollback_candidate_is_authenticated_from_canonical_signed_release(monkeypatch,damage):
    source='f'*40
    candidate={'source_sha':source,'source_tree':'9'*40,'release_stage':'protected-main-source-candidate',
        'commit_verification_status':'VERIFIED','staging_certification':'NOT_RUN_SOURCE_CANDIDATE',
        'kong_image_digest':'sha256:'+'2'*64,'standby_auth_image_digest':'sha256:'+'8'*64,
        'rollback_source_sha':'0'*40,'kong_declarative_config_sha256':'3'*64,
        'kong_image':'kong/kong-gateway:3.14.0.1-ubuntu','standby_auth_image':STANDBY_IMAGE,
        'standby_auth_image_tag':'sha-'+source}
    manifest=json.dumps(candidate).encode()
    buffer=io.BytesIO()
    with zipfile.ZipFile(buffer,'w') as archive:
        archive.writestr('release-manifest.json',manifest)
    raw=buffer.getvalue()
    artifact={'name':'kong-release-'+source,'id':84,'expired':False,'digest':'sha256:'+hashlib.sha256(raw).hexdigest()}
    run={'id':321,'head_sha':source,'head_branch':'main','path':'.github/workflows/release.yml','event':'push',
        'status':'completed','conclusion':'success','repository':{'full_name':verifier.REPOSITORY},
        'head_repository':{'full_name':verifier.REPOSITORY}}
    commit={'sha':source,'commit':{'verification':{'verified':True},'tree':{'sha':'9'*40}}}
    if damage=='unsigned': commit['commit']['verification']['verified']=False
    elif damage=='tree': commit['commit']['tree']['sha']='8'*40
    elif damage=='source': commit['sha']='8'*40
    elif damage=='failed-run': run['conclusion']='failure'
    elif damage=='foreign-repository': run['repository']['full_name']='other/repository'
    elif damage=='tampered-archive': raw+=b'changed'
    replies={'actions/runs/321':json.dumps(run).encode(),'commits/'+source:json.dumps(commit).encode(),
        'actions/runs/321/artifacts?per_page=100':json.dumps({'total_count':1,'artifacts':[artifact]}).encode(),
        'actions/artifacts/84/zip':raw}
    monkeypatch.setattr(verifier,'api',lambda path:replies[path])
    if damage:
        with pytest.raises((ValueError,RuntimeError)):
            verifier.load_rollback_candidate(source,321)
    else:
        actual,proof=verifier.load_rollback_candidate(source,321)
        assert actual==manifest
        assert proof['run_id']==321 and proof['artifact_id']==84
        assert proof['manifest_sha256']==hashlib.sha256(manifest).hexdigest()
