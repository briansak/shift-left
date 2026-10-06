#!/usr/bin/env bash
# Operator-initiated download — Antares-1B into models/1b/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/models/1b"
REPO="${ANTARES_HF_REPO_ID:-fdtn-ai/antares-1b}"

if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

TOKEN="${HF_TOKEN:-${HUGGING_FACE_HUB_TOKEN:-${HUGGINGFACE_HUB_TOKEN:-}}}"
REPO="${ANTARES_HF_REPO_ID:-fdtn-ai/antares-1b}"

if [[ -z "$TOKEN" ]]; then
  echo "Antares download requires HF_TOKEN (gated model)." >&2
  echo "  1. Accept the model agreement at https://huggingface.co/${REPO}" >&2
  echo "  2. Create a token at https://huggingface.co/settings/tokens" >&2
  echo "  3. export HF_TOKEN=...  (or add to .env) and re-run this script" >&2
  exit 1
fi

if ! command -v hf >/dev/null 2>&1; then
  echo "Install the Hugging Face CLI: pip install 'huggingface_hub>=0.28.0'" >&2
  exit 1
fi

mkdir -p "$DEST"

echo "Downloading ${REPO} → ${DEST}"
echo "(Operator-initiated egress — not used at review runtime.)"
echo

set +e
DOWNLOAD_LOG="$(mktemp)"
hf auth login --token "$TOKEN" >/dev/null 2>>"$DOWNLOAD_LOG"
hf download "$REPO" --local-dir "$DEST" --token "$TOKEN" 2>>"$DOWNLOAD_LOG"
STATUS=$?
set -e

if [[ "$STATUS" -ne 0 ]]; then
  if grep -qiE '401|403|gated|authorized|access' "$DOWNLOAD_LOG"; then
    echo "Hugging Face rejected the download for ${REPO}." >&2
    echo "  1. Sign in and accept the model agreement at https://huggingface.co/${REPO}" >&2
    echo "  2. Ensure HF_TOKEN belongs to the account that accepted the terms" >&2
    echo "  3. Re-run: ./scripts/download-antares-model.sh" >&2
    rm -f "$DOWNLOAD_LOG"
    exit 1
  fi
  cat "$DOWNLOAD_LOG" >&2
  rm -f "$DOWNLOAD_LOG"
  exit "$STATUS"
fi
rm -f "$DOWNLOAD_LOG"

if [[ -f "$DEST/config.json" && -f "$DEST/model.safetensors" ]]; then
  echo "Antares download complete."
  echo "Copy config/prewarm-manifest.example.json → models/.prewarm-manifest.json if needed."
else
  echo "Download finished but expected weight files not found under $DEST" >&2
  exit 1
fi
