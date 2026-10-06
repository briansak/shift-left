#!/usr/bin/env bash
# Shift-Left startup self-check (operator-run before docker compose up)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${SHIFT_LEFT_CONFIG:-$ROOT/config/shift-left.yaml}"
ENV_FILE="${ROOT}/.env"
RUNTIME_ONLY=0
if [[ "${1:-}" == "--runtime-only" ]]; then
  RUNTIME_ONLY=1
fi

red() { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

failures=0

check() {
  local name="$1"
  local ok="$2"
  local msg="$3"
  if [[ "$ok" == "1" ]]; then
    green "  [OK] $name — $msg"
  else
    red "  [FAIL] $name — $msg"
    failures=$((failures + 1))
  fi
}

echo "Shift-Left pre-flight self-check"
echo "Root: $ROOT"
echo

# Config file
if [[ -f "$CONFIG" ]]; then
  check "config" 1 "Found $CONFIG"
else
  if [[ -f "$ROOT/config/shift-left.example.yaml" ]]; then
    check "config" 0 "Missing $CONFIG — copy from config/shift-left.example.yaml"
  else
    check "config" 0 "No configuration file found"
  fi
fi

# Env / token
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi
if [[ -n "${FORGEJO_TOKEN:-}" ]]; then
  check "forgejo_token" 1 "FORGEJO_TOKEN is set (bundled-forgejo backend)"
else
  check "forgejo_token" 0 "Set FORGEJO_TOKEN in .env for bundled-forgejo (or token for your git.backend)"
fi

# Local directories
mkdir -p "$ROOT/data/findings" "$ROOT/data/forgejo" "$ROOT/data/postgres" "$ROOT/data/reference" "$ROOT/data/repos"
check "data/findings" 1 "Writable findings directory"
check "data/forgejo" 1 "Forgejo data directory ready"
check "data/postgres" 1 "Postgres data directory ready"

# Antares weights (models/1b — fdtn-ai/antares-1b)
ANTARES_PATH="${ANTARES_MODEL_HOST_PATH:-$ROOT/models/1b}"
if [[ -f "$ANTARES_PATH/config.json" && -f "$ANTARES_PATH/model.safetensors" ]]; then
  check "antares_weights" 1 "Antares 1B weights at $ANTARES_PATH"
  if PYTHONPATH="${ROOT}/services/shift-left-shared${PYTHONPATH:+:$PYTHONPATH}" \
    python3 - "$ROOT" "$ANTARES_PATH" <<'PY' 2>/dev/null
import sys
from pathlib import Path
root = Path(sys.argv[1])
antares = Path(sys.argv[2])
sys.path.insert(0, str(root / "services" / "shift-left-shared"))
from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights
verify_antares_weights(antares, load_prewarm_manifest(root))
    print("ok")
PY
  >/dev/null 2>&1; then
    check "antares_sha256" 1 "Antares SHA256 matches prewarm manifest"
  else
    check "antares_sha256" 0 "Antares SHA256 mismatch — update models/.prewarm-manifest.json"
  fi
else
  check "antares_weights" 0 \
    "Missing Antares weights at $ANTARES_PATH — ./scripts/download-antares-model.sh (HF_TOKEN + gated agreement)"
fi

# Foundation-Sec GGUF (models/foundation-sec-q8_0)
FOUNDATION_PATH="${FOUNDATION_SEC_MODEL_HOST_PATH:-$ROOT/models/foundation-sec-q8_0}"
if compgen -G "$FOUNDATION_PATH"/*.gguf >/dev/null 2>&1; then
  check "foundation_sec_gguf" 1 "Foundation-Sec GGUF at $FOUNDATION_PATH"
  if PYTHONPATH="${ROOT}/services/shift-left-shared${PYTHONPATH:+:$PYTHONPATH}" \
    python3 - "$ROOT" "$FOUNDATION_PATH" <<'PY' 2>/dev/null
import sys
from pathlib import Path
root = Path(sys.argv[1])
fs_dir = Path(sys.argv[2])
sys.path.insert(0, str(root / "services" / "shift-left-shared"))
from shift_left_shared.weights import (
    VERIFIED_FOUNDATION_SEC_Q8_0,
    load_prewarm_manifest,
    verify_gguf_weight,
)
verify_gguf_weight(
    fs_dir,
    load_prewarm_manifest(root),
    manifest_key="foundation-sec",
    verified_meta=VERIFIED_FOUNDATION_SEC_Q8_0,
)
    print("ok")
PY
  >/dev/null 2>&1; then
    check "foundation_sec_sha256" 1 "Foundation-Sec Q8_0 SHA256 matches manifest"
  else
    check "foundation_sec_sha256" 0 "Foundation-Sec SHA256 mismatch — verify staged GGUF"
  fi
elif compgen -G "$FOUNDATION_PATH"/*.gguf.part >/dev/null 2>&1; then
  check "foundation_sec_gguf" 0 \
    "Foundation-Sec GGUF download in progress at $FOUNDATION_PATH (*.gguf.part) — wait for completion"
else
  check "foundation_sec_gguf" 0 \
    "Missing Foundation-Sec GGUF at $FOUNDATION_PATH — stage Q8_0 weights before config reviews"
fi

# Container images (pre-pulled for air-gap) — install-time check only
if [[ "$RUNTIME_ONLY" -eq 0 ]] && command -v docker >/dev/null 2>&1; then
  for image in \
    "postgres:16-alpine" \
    "codeberg.org/forgejo/forgejo:11-rootless" \
    "code.forgejo.org/forgejo/runner:6"; do
    if docker image inspect "$image" >/dev/null 2>&1; then
      check "image:$image" 1 "Present locally"
    else
      check "image:$image" 0 "Not pulled — run 'docker compose pull' while online"
    fi
  done
else
  check "docker" 0 "Docker not installed"
fi

# Lifecycle / sovereignty model
echo
echo "Distribution vs runtime sovereignty:"
echo "  INSTALL/UPDATE: operator-initiated pulls from GitHub, Hugging Face, registries."
echo "  RUNTIME: customer code, configs, findings, inference never egress."
echo "  Verify runtime: ./scripts/shift-left verify-runtime"
echo
echo "Runtime egress controls:"
echo "  - Compose network 'sovereign_internal' (internal: true)"
echo "  - HTTP clients allowlist local services only (see docs/distribution-and-sovereignty.md)"
echo "  - No telemetry, auto-update, or license phone-home (absent by design)"
echo

if [[ "$failures" -gt 0 ]]; then
  red "$failures check(s) failed."
  exit 1
fi

green "All checks passed."
