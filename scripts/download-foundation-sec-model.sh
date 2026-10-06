#!/usr/bin/env bash
# Operator-initiated download — Foundation-Sec Q8_0 GGUF into models/foundation-sec-q8_0/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/models/foundation-sec-q8_0"
REPO="${FOUNDATION_SEC_HF_REPO_ID:-fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF}"
GLOB="${FOUNDATION_SEC_GGUF_GLOB:-foundation-sec-1.1-8b-instruct-q8_0.gguf}"

if [[ -f "${ROOT}/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${ROOT}/.env"
  set +a
fi

TOKEN="${HF_TOKEN:-${HUGGING_FACE_HUB_TOKEN:-${HUGGINGFACE_HUB_TOKEN:-}}}"
REPO="${FOUNDATION_SEC_HF_REPO_ID:-fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF}"

# Large GGUF files often fail via the Xet CDN path (403 on us.aws.cdn.hf.co/xorbs).
# Use legacy HTTP download unless the operator explicitly re-enables Xet.
export HF_HUB_DISABLE_XET="${HF_HUB_DISABLE_XET:-1}"

if ! command -v hf >/dev/null 2>&1; then
  echo "Install the Hugging Face CLI: brew install hf" >&2
  exit 1
fi

mkdir -p "$DEST"
rm -f "$DEST"/*.part "$DEST"/.*.incomplete 2>/dev/null || true

echo "Downloading ${REPO} → ${DEST}"
echo "(Operator-initiated egress — not used at review runtime.)"
if [[ "${HF_HUB_DISABLE_XET}" == "1" ]]; then
  echo "(HF_HUB_DISABLE_XET=1 — legacy HTTP download; avoids Xet CDN 403 failures.)"
fi
echo

HF_ARGS=(download "$REPO" --local-dir "$DEST" --include "$GLOB")
if [[ -n "$TOKEN" ]]; then
  hf auth login --token "$TOKEN" >/dev/null
  HF_ARGS+=(--token "$TOKEN")
fi

set +e
DOWNLOAD_LOG="$(mktemp)"
hf "${HF_ARGS[@]}" 2>>"$DOWNLOAD_LOG"
STATUS=$?
set -e

if [[ "$STATUS" -ne 0 ]]; then
  if grep -qiE 'xet_get|xorbs|cdn\.hf\.co' "$DOWNLOAD_LOG"; then
    echo "Hugging Face Xet CDN rejected the download for ${REPO}." >&2
    echo "  This is usually not an auth/token problem." >&2
    echo "  Re-run with legacy HTTP download (default in this script):" >&2
    echo "    HF_HUB_DISABLE_XET=1 ./scripts/download-foundation-sec-model.sh" >&2
    echo "  Or update hf-xet: pip install -U hf-xet" >&2
  elif grep -qiE '401|gated|not authorized|accept.*terms|repository.*access' "$DOWNLOAD_LOG"; then
    echo "Hugging Face rejected the download for ${REPO} (authentication or gated access)." >&2
    echo "  1. Open https://huggingface.co/${REPO} and accept terms if prompted" >&2
    echo "  2. Set HF_TOKEN in .env to a read token for that account" >&2
    echo "  3. Re-run: ./scripts/download-foundation-sec-model.sh" >&2
  else
    cat "$DOWNLOAD_LOG" >&2
  fi
  rm -f "$DOWNLOAD_LOG"
  exit 1
fi
rm -f "$DOWNLOAD_LOG"

if compgen -G "$DEST"/*.gguf >/dev/null; then
  ls -lh "$DEST"/*.gguf
  echo
  echo "Foundation-Sec GGUF download complete."
else
  echo "Download finished but no .gguf file found under $DEST" >&2
  exit 1
fi
