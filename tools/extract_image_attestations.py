#!/usr/bin/env python3
"""Extract and bind the SBOM and provenance attestations of a published image.

``docker buildx imagetools inspect <image>@<digest> --format '{{ json .SBOM }}'``
and ``'{{ json .Provenance }}'`` return the attestations BuildKit attached to
the image index (keyed by platform for multi-platform images). This tool
extracts the SPDX document, proves the provenance is a BuildKit SLSA statement
for the expected source revision when it carries VCS metadata, writes the SBOM
to a standalone file and emits the sha256 of both files for the release manifest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\Z")
MAX_DOCUMENT = 32 * 1024 * 1024


class AttestationError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AttestationError(reason)


def _single_platform(document: dict, key: str) -> dict:
    """``{"SPDX": {...}}`` for one platform or ``{"linux/amd64": {"SPDX": {...}}}`` for several."""
    if key in document:
        return document
    platforms = {name: value for name, value in document.items() if isinstance(value, dict) and key in value}
    require(len(platforms) == 1, f"attestation_platforms:{sorted(document)}")
    return next(iter(platforms.values()))


def extract_sbom(document: dict) -> dict:
    require(isinstance(document, dict) and document, "sbom_attestation_missing")
    spdx = _single_platform(document, "SPDX")["SPDX"]
    require(isinstance(spdx, dict) and str(spdx.get("spdxVersion", "")).startswith("SPDX-"), "sbom_not_spdx")
    packages = spdx.get("packages")
    require(isinstance(packages, list) and len(packages) > 0, "sbom_without_packages")
    return spdx


def check_provenance(document: dict, expected_revision: str) -> dict:
    require(SHA.fullmatch(expected_revision or "") is not None, "expected_revision_format")
    require(isinstance(document, dict) and document, "provenance_attestation_missing")
    slsa = _single_platform(document, "SLSA")["SLSA"]
    require(isinstance(slsa, dict), "provenance_not_slsa")
    # SLSA v0.2 carries buildType at the top level; SLSA v1 nests it in buildDefinition.
    build_type = str(slsa.get("buildType") or (slsa.get("buildDefinition") or {}).get("buildType") or "")
    require("buildkit" in build_type.lower(), f"provenance_build_type:{build_type}")
    metadata = slsa.get("metadata") or (slsa.get("runDetails") or {}).get("metadata") or {}
    require((metadata.get("completeness") or {}).get("parameters") is not False, "provenance_incomplete_parameters")
    # BuildKit records VCS facts under "https://mobyproject.org/buildkit@v1#metadata" (v0.2)
    # or a similarly named extension key; the revision must match when it is present.
    revision = None
    for key, value in metadata.items():
        if "buildkit" in str(key).lower() and isinstance(value, dict):
            revision = (value.get("vcs") or {}).get("revision", revision)
    if revision is not None:
        require(revision == expected_revision, f"provenance_revision:{revision}")
    return {"buildType": build_type, "revision": revision}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sbom-attestation", type=Path, required=True)
    parser.add_argument("--sbom-output", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        raw_sbom = args.sbom_attestation.read_bytes()
        raw_provenance = args.provenance.read_bytes()
        require(len(raw_sbom) <= MAX_DOCUMENT and len(raw_provenance) <= MAX_DOCUMENT, "attestation_too_large")
        spdx = extract_sbom(json.loads(raw_sbom))
        provenance = check_provenance(json.loads(raw_provenance), args.expected_revision)
        args.sbom_output.write_text(json.dumps(spdx, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        sbom_sha256 = hashlib.sha256(args.sbom_output.read_bytes()).hexdigest()
        provenance_sha256 = hashlib.sha256(raw_provenance).hexdigest()
    except (AttestationError, OSError, ValueError, TypeError, KeyError) as error:
        print(f"IMAGE_ATTESTATIONS=FAIL {error}")
        return 2
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as out:
            out.write(f"sbom_sha256={sbom_sha256}\nprovenance_sha256={provenance_sha256}\n")
    print("IMAGE_ATTESTATIONS=PASS")
    print(f"SBOM_SHA256={sbom_sha256}")
    print(f"PROVENANCE_SHA256={provenance_sha256}")
    print(f"PROVENANCE_BUILD_TYPE={provenance['buildType']} PROVENANCE_REVISION={provenance['revision']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
