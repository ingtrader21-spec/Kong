from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MIGRATION_MANIFEST.json"

def main() -> None:
    data = json.loads(MANIFEST.read_text())
    assert data["schema"] == "codestra.kong.repository-migration.v1"
    assert data["production_state_changed"] is False
    for row in data["files"]:
        path = ROOT / row["path"]
        assert path.is_file(), row["path"]
        assert path.stat().st_size == row["size"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"]
    print(f"MIGRATION_MANIFEST=PASS FILES={len(data['files'])}")

if __name__ == "__main__":
    main()
