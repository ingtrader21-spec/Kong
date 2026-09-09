#!/usr/bin/env bash
set -Eeuo pipefail
# Read-only capture uses the existing authorized local Docker operator path.
# No host Admin listener, Docker permission change, or service action is created.
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-${RUNNER_TEMP:-/tmp}/kong-production-readback.json}"
if (( $# )); then shift; fi
exec python3 "$root/tools/capture_kong_server_baseline.py" "$output" "$@"
