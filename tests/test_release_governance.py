import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "tools/generate_release_manifest.py"


def module():
    spec = importlib.util.spec_from_file_location("generate_release_manifest", GENERATOR)
    assert spec and spec.loader
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def test_release_image_requires_immutable_sha256_digest():
    pattern = module().IMAGE_DIGEST
    assert pattern.fullmatch("sha256:" + "a" * 64)
    assert not pattern.fullmatch("latest")
    assert not pattern.fullmatch("sha256:abc")
    assert not pattern.fullmatch("sha256:" + "A" * 64)


def test_release_signature_must_be_verified():
    verified = module().VERIFIED_SIGNATURES
    assert {"G", "U", "VERIFIED"} <= verified
    assert "N" not in verified
    assert "UNVERIFIED" not in verified


def test_staging_promotion_requires_exact_main_head():
    workflow = (ROOT / ".github/workflows/staging-certification.yml").read_text()
    assert 'test "$HEAD_REF" = main' in workflow
    assert 'test "$HEAD_SHA" = "$(git rev-parse origin/main)"' in workflow
