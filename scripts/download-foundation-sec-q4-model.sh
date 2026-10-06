#!/usr/bin/env bash
# Operator-initiated download — Foundation-Sec Q4_K_M GGUF (default profile)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${ROOT}/models/foundation-sec-q4_k_m"
PY="${ROOT}/.venv/bin/python3"

export PYTHONPATH="${ROOT}/cli:${ROOT}/services/shift-left-shared${PYTHONPATH:+:$PYTHONPATH}"
export HF_HUB_DISABLE_XET="${HF_HUB_DISABLE_XET:-1}"

if [[ ! -x "$PY" ]]; then
  echo "Missing ${ROOT}/.venv — run ./shift-left up once to bootstrap Python." >&2
  echo "Or copy weights to ${DEST}/foundation-sec-1.1-8b-instruct-q4_k_m.gguf" >&2
  exit 1
fi

CERT="$("$PY" -m certifi 2>/dev/null || true)"
if [[ -n "$CERT" ]]; then
  export SSL_CERT_FILE="$CERT"
  export REQUESTS_CA_BUNDLE="$CERT"
fi

"$PY" -c "
from pathlib import Path
from shift_left_cli.hf_download import download_repo_file
from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_Q4_K_M

root = Path('${ROOT}')
dest = root / 'models' / 'foundation-sec-q4_k_m'
meta = VERIFIED_FOUNDATION_SEC_Q4_K_M
if (dest / meta['gguf_filename']).is_file() or any(dest.glob('*.gguf')):
    print(f\"Foundation-Sec Q4_K_M already staged under {dest.relative_to(root)}/\")
    raise SystemExit(0)
download_repo_file(
    root,
    repo_id=meta['hf_repo_id'],
    filename=meta['gguf_filename'],
    dest_dir=dest,
)
print('Foundation-Sec Q4_K_M download complete.')
"
