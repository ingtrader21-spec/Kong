#!/usr/bin/env python3
"""Package approved observations on the protected runtime runner; never run probes."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools import kong_certification as evidence
from tools.verify_staging_certification import load_rollback_candidate


def read_observation(path: Path, expected_hash: str) -> bytes:
    evidence.require(isinstance(expected_hash, str) and bool(evidence.HASH.fullmatch(expected_hash)),
                     "approved_observation_hash_missing")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        evidence.require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0 and
                         metadata.st_nlink == 1 and not metadata.st_mode & 0o022 and
                         metadata.st_size <= evidence.MAX_DOCUMENT, "untrusted_observation_file")
        raw = stream.read(evidence.MAX_DOCUMENT + 1)
    evidence.require(len(raw) <= evidence.MAX_DOCUMENT and hashlib.sha256(raw).hexdigest() == expected_hash,
                     "approved_observation_hash_mismatch")
    return raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--observation-sha256", required=True)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence.require(bool(evidence.SHA.fullmatch(args.source_sha)), "invalid_source")
        raw = read_observation(Path("/var/lib/codestra/kong-certification") / args.source_sha / "certification.json",
                               args.observation_sha256)
        candidate_raw = args.candidate_manifest.read_bytes()
        evidence.require(evidence.decode(candidate_raw).get("source_sha") == args.source_sha, "wrong_candidate")
        inventory_raw = (evidence.ROOT / "config/kong-production-route-inventory.v2.json").read_bytes()
        rollback_raw, _ = load_rollback_candidate(evidence.decode(candidate_raw).get("rollback_source_sha"),
            evidence.decode(raw).get("rollback", {}).get("candidate_run_id"))
        evidence.validate_bytes(raw, candidate_raw, inventory_raw, rollback_candidate=evidence.decode(rollback_raw))
        with args.output.open("xb") as output:
            output.write(raw)
        print("KONG_STAGING_OBSERVATIONS=VALIDATED")
        print("RUNTIME_PROBES_EXECUTED=NO")
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        print("KONG_STAGING_OBSERVATIONS=FAIL")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
