"""Synthetic Git/Actions fixtures; these are not runtime certification evidence."""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


def run_fixture():
    return {'id': 123, 'head_sha': 'a'*40, 'head_branch': 'main',
            'path': '.github/workflows/release.yml', 'event': 'push', 'status': 'completed',
            'conclusion': 'success', 'repository': {'full_name': 'appolon1908-hue/Kong'},
            'head_repository': {'full_name': 'appolon1908-hue/Kong'}}


@pytest.mark.parametrize('change', [
    {'id': 999}, {'head_sha': 'b'*40}, {'head_branch': 'feature'}, {'conclusion': 'failure'},
    {'status': 'in_progress'}, {'event': 'pull_request'}, {'path': '.github/workflows/other.yml'},
    {'head_repository': {'full_name': 'untrusted/fork'}}, {'repository': {'full_name': 'wrong/repo'}},
])
def test_only_successful_canonical_main_runs_are_accepted(change):
    m = load('verify_release_candidate'); run = run_fixture(); m.validate_run(run, 'a'*40, 123)
    run.update(change)
    with pytest.raises(ValueError): m.validate_run(run, 'a'*40, 123)


def artifact_fixture():
    manifest = {'release_stage': 'protected-main-source-candidate', 'source_sha': 'a'*40,
        'source_tree': 'c'*40, 'commit_verification_status': 'VERIFIED',
        'staging_certification': 'NOT_RUN_SOURCE_CANDIDATE', 'rollback_source_sha': 'd'*40,
        'kong_image': 'kong/kong-gateway:3.14.0.1-ubuntu',
        'standby_auth_image': 'ghcr.io/appolon1908-hue/kong-standby-auth',
        'kong_image_digest': 'sha256:'+'a'*64, 'standby_auth_image_digest': 'sha256:'+'b'*64}
    return manifest


def zip_manifest(manifest, extra=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as z:
        z.writestr('release-manifest.json', json.dumps(manifest))
        if extra: z.writestr(extra, 'not-executed')
    raw = out.getvalue()
    artifact = {'id': 42, 'name': 'kong-release-'+'a'*40, 'expired': False,
                'digest': 'sha256:'+hashlib.sha256(raw).hexdigest()}
    return raw, artifact


@pytest.mark.parametrize('change', [{'expired': True}, {'digest': None}, {'id': -1}, {'name': 'other'}])
def test_missing_expired_or_unbound_artifacts_rejected(change):
    m=load('verify_release_candidate'); _, artifact=zip_manifest(artifact_fixture())
    assert m.select_artifact({'total_count':1,'artifacts':[artifact]},'a'*40)==artifact
    artifact.update(change)
    with pytest.raises(ValueError): m.select_artifact({'total_count':1,'artifacts':[artifact]},'a'*40)


@pytest.mark.parametrize('total,repeat', [(2,1),(2,2)])
def test_incomplete_or_ambiguous_artifact_sets_rejected(total, repeat):
    m=load('verify_release_candidate'); _, artifact=zip_manifest(artifact_fixture())
    with pytest.raises(ValueError): m.select_artifact({'total_count':total,'artifacts':[artifact]*repeat},'a'*40)


@pytest.mark.parametrize('damage', ['archive-digest','traversal','source','image','unresolved','stage','signature'])
def test_artifact_bytes_and_source_authority_are_bound(damage):
    m=load('verify_release_candidate'); manifest=artifact_fixture()
    if damage=='source': manifest['source_sha']='b'*40
    if damage=='image': manifest['standby_auth_image']='untrusted/image'
    if damage=='unresolved': manifest['kong_image_digest']='latest'
    if damage=='stage': manifest['release_stage']='production'
    if damage=='signature': manifest['commit_verification_status']='N'
    raw, artifact=zip_manifest(manifest,'../escape' if damage=='traversal' else None)
    if damage=='archive-digest': raw+=b'tampered'
    with pytest.raises(ValueError): m.verified_manifest(raw,artifact,'a'*40)


def test_valid_artifact_is_read_not_executed():
    m=load('verify_release_candidate'); manifest=artifact_fixture(); raw,artifact=zip_manifest(manifest)
    _, verified=m.verified_manifest(raw,artifact,'a'*40)
    assert verified==manifest


def git(root, *args):
    return subprocess.check_output(['git','-C',str(root),*args],text=True,stderr=subprocess.DEVNULL).strip()


@pytest.fixture
def release_repository(tmp_path, monkeypatch):
    root=tmp_path/'repo'; root.mkdir()
    git(root,'init','-b','main'); git(root,'config','user.name','Synthetic Test')
    git(root,'config','user.email','test@example.invalid')
    (root/'deploy/kong').mkdir(parents=True)
    (root/'deploy/kong/control-plane.yml').write_text('services: []\n')
    (root/'MIGRATION_MANIFEST.yaml').write_text('manifest_generation_id: synthetic-fixture\n')
    (root/'MIGRATION_MANIFEST.json').write_text('{"manifest_generation_id":"synthetic-fixture"}\n')
    git(root,'add','.'); git(root,'commit','-m','base')
    base=git(root,'rev-parse','HEAD')
    (root/'payload').write_text('reviewed source bytes\n')
    git(root,'add','.'); git(root,'commit','-m','reviewed candidate')
    source=git(root,'rev-parse','HEAD')
    m=load('generate_release_manifest'); monkeypatch.setattr(m,'ROOT',root)
    candidate=tmp_path/'candidate.json'
    def invoke(stage, output, cert='NOT_RUN_SOURCE_CANDIDATE', extra=()):
        monkeypatch.setattr(sys,'argv',['generate','--output',str(output),'--release-stage',stage,
            '--commit-verification-status','VERIFIED','--kong-image-digest','sha256:'+'a'*64,
            '--standby-auth-image-digest','sha256:'+'b'*64,'--rollback-source-sha',base,
            '--staging-certification',cert,*extra])
        return m.main()
    assert invoke(m.SOURCE_RELEASE_STAGE,candidate)==0
    args=['--certified-source-sha',source,'--candidate-manifest',str(candidate),
          '--candidate-manifest-sha256',hashlib.sha256(candidate.read_bytes()).hexdigest(),
          '--candidate-run-id','123','--candidate-artifact-id','42']
    return root, base, source, candidate, args, invoke, m


@pytest.mark.parametrize('method', ['merge','squash','rebase'])
def test_normal_promotion_preserves_certified_source_and_exact_artifacts(release_repository, method, tmp_path):
    root,base,source,candidate,args,invoke,m=release_repository
    git(root,'checkout','-b','target',base)
    git(root,'commit','--allow-empty','-m','destination identity')
    if method=='merge': git(root,'merge','--no-ff','main','-m','promotion')
    elif method=='squash':
        git(root,'merge','--squash','main'); git(root,'commit','-m','squashed promotion')
    else:
        git(root,'checkout','-b','replayed',source)
        git(root,'rebase','--onto','target',base)
    destination=git(root,'rev-parse','HEAD'); assert destination!=source
    assert git(root,'rev-parse','HEAD^{tree}')==git(root,'rev-parse',source+'^{tree}')
    output=tmp_path/'promotion.json'
    assert invoke(m.STAGING_RELEASE_STAGE,output,'PASS:'+source+':synthetic-only',args)==0
    doc=json.loads(output.read_text()); original=json.loads(candidate.read_text())
    assert doc['source_sha']==source and doc['promotion_sha']==destination
    for key in ('kong_image_digest','standby_auth_image_digest','rollback_source_sha','source_tree'):
        assert doc[key]==original[key]
    assert doc['runtime_apply_authorized'] is doc['external_effects_enabled'] is False
    assert invoke(m.PRODUCTION_RELEASE_STAGE,output,'PASS:'+destination+':wrong-identity',args)==2


@pytest.mark.parametrize('damage', ['tree','digest','manifest-checksum','rollback','unbound-source','missing-artifact'])
def test_changed_promotion_tuple_is_rejected(release_repository, tmp_path, damage):
    root,base,source,candidate,args,invoke,m=release_repository
    if damage=='tree':
        (root/'payload').write_text('changed')
        git(root,'add','.'); git(root,'commit','-m','not certified')
    elif damage=='unbound-source': args[1]='b'*40
    elif damage=='missing-artifact': args[-1]='0'
    else:
        doc=json.loads(candidate.read_text())
        if damage=='digest': doc['kong_image_digest']='sha256:'+'c'*64
        elif damage=='rollback': doc['rollback_source_sha']='c'*40
        else: doc['unreviewed']='mutation'
        candidate.write_text(json.dumps(doc))
        if damage!='manifest-checksum': args[5]=hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert invoke(m.STAGING_RELEASE_STAGE,tmp_path/'blocked.json','PASS:'+source+':fixture',args)==2


def test_every_build_and_tag_resolution_step_is_main_only():
    workflow=yaml.safe_load((ROOT/'.github/workflows/release.yml').read_text())
    job=workflow['jobs']['release-evidence']
    assert job['environment']=='${{ github.ref_name }}'
    assert workflow['permissions']['actions']=='read'
    for step in job['steps']:
        if 'docker buildx build' in step.get('run','') or '${KONG_IMAGE_REF}' in step.get('run',''):
            assert step.get('if')=="github.ref_name == 'main'"
    capture=yaml.safe_load((ROOT/'.github/workflows/server-drift.yml').read_text())['jobs']['server-drift']
    assert capture['runs-on']==['self-hosted','linux','kong-runtime']
    assert 'GITHUB_REF_PROTECTED' in capture['steps'][1]['run']
