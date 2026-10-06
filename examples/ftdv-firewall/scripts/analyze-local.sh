#!/usr/bin/env bash
# Evaluate all Terraform in this project via local Foundation-Sec (no FMC apply).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TF_DIR="$ROOT/terraform"
FS_URL="${FOUNDATION_SEC_SERVICE_URL:-http://127.0.0.1:8091}"

if ! curl -fsS "$FS_URL/health" >/dev/null; then
  echo "Foundation-Sec not reachable at $FS_URL" >&2
  echo "Start it with FOUNDATION_SEC_ENGINE=scripted foundation-sec-server (see repo README)." >&2
  exit 1
fi

python3 - "$TF_DIR" <<'PY' | curl -fsS "$FS_URL/v1/analyze" \
  -H 'Content-Type: application/json' \
  -d @- | python3 -m json.tool
import json
import pathlib
import sys

tf_dir = pathlib.Path(sys.argv[1])
files = []
for path in sorted(tf_dir.rglob("*.tf")):
    if ".terraform" in path.parts:
        continue
    text = path.read_text(encoding="utf-8")
    rel = path.relative_to(tf_dir.parent).as_posix()
    lines = max(1, text.count("\n") + (0 if text.endswith("\n") or not text else 1))
    files.append(
        {
            "path": rel,
            "hunks": [{"new_start": 1, "new_end": lines, "content": text}],
        }
    )

payload = {
    "repo": "local/ftdv-firewall",
    "pr_ref": "local-eval",
    "commit_sha": "local",
    "files": files,
}
print(json.dumps(payload))
PY
