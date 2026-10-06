#!/usr/bin/env bash
# One-time Forgejo Actions runner registration (run while Forgejo is up)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FORGEJO_URL="${FORGEJO_ROOT_URL:-http://localhost:3000}"

echo "Register Forgejo runner against $FORGEJO_URL"
echo "Generate a runner token in Forgejo: Admin → Actions → Runners → Create new runner"
echo

docker compose run --rm forgejo-runner forgejo-runner register \
  --no-interactive \
  --instance "$FORGEJO_URL" \
  --token "${FORGEJO_RUNNER_TOKEN:?Set FORGEJO_RUNNER_TOKEN}" \
  --name "${FORGEJO_RUNNER_NAME:-shift-left-runner}" \
  --labels "${FORGEJO_RUNNER_LABELS:-self-hosted:host}"

echo "Runner registered. Start with: docker compose up -d forgejo-runner"
