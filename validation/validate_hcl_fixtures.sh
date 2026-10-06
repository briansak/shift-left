#!/usr/bin/env bash
# Validate cisco_ftd corpus fixtures against CiscoDevNet/fmc 2.0.1 via terraform validate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="${ROOT}/services/orchestrator/.venv/bin/python"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="$(command -v python3)"
fi

CORPUS_DIRS=(
  "$ROOT/validation/corpus/config/cisco_ftd"
  "$ROOT/validation/corpus/holdout/cisco_ftd"
)

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/fmc-validate.XXXXXX")"
export TF_PLUGIN_CACHE_DIR="${TMP_ROOT}/plugin-cache"
mkdir -p "$TF_PLUGIN_CACHE_DIR"
trap 'rm -rf "$TMP_ROOT"' EXIT

pass_count=0
fail_count=0
total=0

echo "FMC HCL fixture validation (CiscoDevNet/fmc 2.0.1)"
echo "Schema: validation/schemas/fmc-2.0.1-schema.json"
echo

for corpus_dir in "${CORPUS_DIRS[@]}"; do
  [[ -d "$corpus_dir" ]] || continue
  while IFS= read -r -d '' fixture; do
    total=$((total + 1))
    rel="${fixture#"$ROOT"/}"
    work_dir="$TMP_ROOT/$(echo "$rel" | tr '/.' '__')"
    mkdir -p "$work_dir"
    "$PYTHON" "$SCRIPT_DIR/scripts/prepare_validate_module.py" "$fixture" "$work_dir" >/dev/null
    if (
      cd "$work_dir"
      for attempt in 1 2 3; do
        if terraform init -input=false -no-color >/dev/null 2>&1; then
          break
        fi
        sleep 1
      done
      terraform validate -no-color
    ) >/tmp/fmc-validate-out.$$ 2>&1; then
      pass_count=$((pass_count + 1))
      printf 'PASS  %s\n' "$rel"
    else
      fail_count=$((fail_count + 1))
      printf 'FAIL  %s\n' "$rel"
      sed 's/^/      /' /tmp/fmc-validate-out.$$
    fi
    rm -f /tmp/fmc-validate-out.$$
  done < <(find "$corpus_dir" -name '*.tf' -type f -print0 | sort -z)
done

echo
echo "Summary: ${pass_count}/${total} passed, ${fail_count} failed"
if [[ "$fail_count" -gt 0 ]]; then
  exit 1
fi
