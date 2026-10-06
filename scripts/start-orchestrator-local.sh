#!/usr/bin/env bash
# Start the orchestrator on the host for local UI / dev (not Docker).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${SHIFT_LEFT_CONFIG:-$ROOT/config/shift-left.yaml}"

if [[ ! -f "$CONFIG" ]]; then
  echo "Missing config: $CONFIG" >&2
  echo "Copy config/shift-left.example.yaml to config/shift-left.yaml and adjust." >&2
  exit 1
fi

mkdir -p "$ROOT/data/findings" "$ROOT/data/reference" "$ROOT/data/repos"

export SHIFT_LEFT_CONFIG="$CONFIG"
export SHIFT_LEFT_SKIP_EGRESS_PROBE="${SHIFT_LEFT_SKIP_EGRESS_PROBE:-1}"

if [[ -z "${FORGEJO_TOKEN:-}" ]]; then
  echo "Warning: FORGEJO_TOKEN is unset — startup self-check will fail unless you set it." >&2
  echo "Mint or copy a Forgejo API token into your environment." >&2
fi

cd "$ROOT/services/orchestrator"
exec "$ROOT/.venv/bin/python3" -m shift_left.main
