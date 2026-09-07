#!/usr/bin/env python3
"""Download only a digest-bound artifact from a successful canonical main release.

Requires an already authorized read-only GitHub token. Never builds images,
updates refs, changes protected variables, or executes artifact contents.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import zipfile

REPOSITORY = 'appolon1908-hue/Kong'
SHA = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_MANIFEST = 1024 * 1024


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def api(path: str) -> bytes:
    result = subprocess.run(['gh', 'api', f'repos/{REPOSITORY}/{path}'],
                            capture_output=True, timeout=60, check=False)
    require(result.returncode == 0 and len(result.stdout) <= MAX_ARCHIVE, 'github_read_failed')
    return result.stdout


def validate_run(run: dict, source: str, run_id: int) -> None:
    require(run.get('id') == run_id and run.get('head_sha') == source, 'wrong_run_identity')
    require(run.get('head_branch') == 'main' and run.get('path') == '.github/workflows/release.yml',
            'not_canonical_release')
    require(run.get('event') in {'push', 'workflow_dispatch'} and
            run.get('status') == 'completed' and run.get('conclusion') == 'success', 'release_not_successful')
    for field in ('repository', 'head_repository'):
        require(run.get(field, {}).get('full_name') == REPOSITORY, 'foreign_repository')


def select_artifact(page: dict, source: str) -> dict:
    items = page.get('artifacts')
    require(isinstance(items, list) and page.get('total_count') == len(items), 'incomplete_artifact_list')
    matches = [item for item in items if item.get('name') == 'kong-release-' + source]
    require(len(matches) == 1, 'missing_or_ambiguous_artifact')
    artifact = matches[0]
    require(artifact.get('expired') is False, 'expired_artifact')
    require(type(artifact.get('id')) is int and artifact['id'] > 0, 'invalid_artifact_id')
    require(isinstance(artifact.get('digest'), str) and bool(DIGEST.fullmatch(artifact['digest'])),
            'artifact_digest_missing')
    return artifact


def verified_manifest(archive: bytes, artifact: dict, source: str) -> tuple[bytes, dict]:
    require(len(archive) <= MAX_ARCHIVE and
            'sha256:' + hashlib.sha256(archive).hexdigest() == artifact['digest'], 'artifact_digest_mismatch')
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        entries = bundle.infolist()
        names = [item.filename for item in entries]
        require(len(names) == len(set(names)), 'duplicate_zip_member')
        require('release-manifest.json' in names, 'manifest_missing')
        for item in entries:
            require('/' not in item.filename and '\\' not in item.filename and
                    not stat.S_ISLNK(item.external_attr >> 16), 'unsafe_archive_member')
            require(item.file_size <= MAX_MANIFEST, 'oversized_archive_member')
        raw = bundle.read('release-manifest.json')
    manifest = json.loads(raw)
    require(isinstance(manifest, dict) and manifest.get('source_sha') == source, 'wrong_candidate_source')
    require(manifest.get('release_stage') == 'protected-main-source-candidate', 'not_source_candidate')
    require(manifest.get('commit_verification_status') in {'G', 'U', 'VERIFIED'}, 'unverified_source')
    require(manifest.get('staging_certification') == 'NOT_RUN_SOURCE_CANDIDATE', 'invalid_source_stage')
    for field in ('kong_image_digest', 'standby_auth_image_digest'):
        require(isinstance(manifest.get(field), str) and bool(DIGEST.fullmatch(manifest[field])), 'invalid_image_digest')
    require(SHA.fullmatch(manifest.get('source_tree', '')) is not None, 'invalid_source_tree')
    require(SHA.fullmatch(manifest.get('rollback_source_sha', '')) is not None, 'invalid_rollback')
    require(manifest.get('kong_image') == 'kong/kong-gateway:3.14.0.1-ubuntu' and
            manifest.get('standby_auth_image') == 'ghcr.io/appolon1908-hue/kong-standby-auth', 'wrong_image_authority')
    return raw, manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--github-output', required=True, type=Path)
    args = parser.parse_args()
    try:
        require(bool(SHA.fullmatch(args.source_sha)) and args.run_id > 0, 'invalid_candidate_identity')
        run = json.loads(api(f'actions/runs/{args.run_id}'))
        validate_run(run, args.source_sha, args.run_id)
        commit = json.loads(api(f'commits/{args.source_sha}'))
        require(commit.get('sha') == args.source_sha and
                commit.get('commit', {}).get('verification', {}).get('verified') is True, 'unsigned_source')
        artifact = select_artifact(json.loads(api(f'actions/runs/{args.run_id}/artifacts?per_page=100')), args.source_sha)
        raw, manifest = verified_manifest(api(f'actions/artifacts/{artifact["id"]}/zip'), artifact, args.source_sha)
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        (args.output_dir / 'release-manifest.json').write_bytes(raw)
        receipt = {'schema': 'codestra.kong.candidate-receipt.v1', 'repository': REPOSITORY,
                   'source_sha': args.source_sha, 'run_id': args.run_id, 'artifact_id': artifact['id'],
                   'artifact_digest': artifact['digest'], 'manifest_sha256': hashlib.sha256(raw).hexdigest()}
        (args.output_dir / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        with args.github_output.open('a') as out:
            for name, value in {
                'kong_digest': manifest['kong_image_digest'], 'standby_digest': manifest['standby_auth_image_digest'],
                'rollback_source_sha': manifest['rollback_source_sha'],
                'manifest_sha256': receipt['manifest_sha256'], 'artifact_id': artifact['id'],
            }.items():
                out.write(f'{name}={value}\n')
        print('KONG_CANDIDATE_ARTIFACT=PASS')
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, RecursionError, zipfile.BadZipFile, subprocess.SubprocessError):
        print('KONG_CANDIDATE_ARTIFACT=FAIL')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
