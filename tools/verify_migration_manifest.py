from __future__ import annotations

import hashlib
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MIGRATION_MANIFEST.yaml"

def main() -> None:
    data = yaml.safe_load(MANIFEST.read_text())
    assert data["schema"] == "codestra.kong.repository-migration.v1"
    assert data["production_state_changed"] is False
    for row in data["files"]:
        path = ROOT / row["path"]
        assert path.is_file(), row["path"]
        assert path.stat().st_size == row["size"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
    expected = {
        path.relative_to(ROOT).as_posix()
        for top in ("config", "deploy", "docs", "operations", "scripts", "tests", "tools")
        for path in (ROOT / top).rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    } | {".github/workflows/validate.yml", ".gitignore", "README.md", "SECURITY.md", "pytest.ini"}
    expected.discard("MIGRATION_MANIFEST.yaml")
    assert {row["path"] for row in data["files"]} == expected
    print(f"MIGRATION_MANIFEST=PASS FILES={len(data['files'])}")

if __name__ == "__main__":
    main()
