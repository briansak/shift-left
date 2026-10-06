# Antares triage

This document is for operators who want advisory CWE localization across a repository snapshot. It is not part of the PR merge gate. Token capabilities: [auth-tokens.md](auth-tokens.md). HTTP: [api-guide.md](api-guide.md).

Antares is optional and off by default (`models.antares.enabled`, `antares_triage.enabled`, and both `installed` flags start false). `./shift-left install-antares` sets those enabled flags true when it stages the server. Then `./shift-left model start antares-server`. The minimum staged variant is **1B** (`fdtn-ai/antares-1b`). 350M is below `antares_triage.minimum_variant` and is not used for triage.

## What it produces

- Ranked candidate files for human review (no line ranges)
- An exploration trace of read-only terminal tool calls
- A `LocalizationResult` (`is_advisory` always true)

Output is never a `Finding`, never a policy input, and never blocks a merge. Referencing `LocalizationResult` fields in a policy rule is a load-time validation error.

Present results as candidate files, not as confirmed vulnerabilities.

## Launch

Primary path: `POST /api/v1/investigations` (queued, UI-backed) with `repo`, `ref`, and `task_cwe`. Optional `advisory_cve` resolves CWE from the **local** reference cache only and fails closed if the CVE is absent.

Batch: `POST /api/v1/investigation-batches` with `source` `top25`, `profiled`, or `custom`. Guardrails: `investigations.batch.size_cap` (25) and `confirm_threshold` (10). Runs queue one at a time.

`POST /api/v1/triage/antares` still exists as a synchronous call. Prefer investigations for anything the UI should track.

Automatic CWE nomination from a PR diff is not implemented.

The operator checkout is `{antares_triage.repos_checkout_dir}/{owner}/{repo}` (repo-relative `data/repos`, remapped in Compose via `SHIFT_LEFT_DATA_DIR`). Before each run the server **materializes a hardened snapshot** (symlinks discarded, path escapes rejected, external hardlinks omitted). The live checkout is never bind-mounted into the sandbox.

## Agent loop

- CWE-conditioned system prompt
- Read-only tools (`grep`, `find`, `cat`, `ls`, `head`, …) — allowlist in `sandbox_policy.py`
- Up to 15 terminal calls (`models.antares.agent.max_terminal_calls`)
- Stop via `submit_vulnerable_files` or `submit_no_vulnerability_found` (the latter is success)
- Temperature 0.3, top_p 1.0

Candidate disposition: `PATCH /api/v1/investigations/{id}/candidates/{rank}/disposition` (and the investigation HTML form).

## Sandbox

Each investigation uses a dedicated Docker container next to host-native `antares-server`:

| Control | Value |
|---------|-------|
| Network | `network=none` |
| Repo | read-only at `/workspace/repo` (snapshot, not the live checkout) |
| Per-command timeout | 10 seconds |
| CPU / memory | 2 CPUs, 4 GB (`ANTARES_SANDBOX_CPUS` / `ANTARES_SANDBOX_MEMORY`) |
| Lifetime | container destroyed when the run finishes or fails |
| Commands | allowlist only; no interpreters, no repo scripts |

`antares-server` talks to the host Docker Engine via `/var/run/docker.sock` (or `DOCKER_HOST`). Restrict who can run that process.

```bash
docker build -f services/antares-server/Dockerfile.sandbox -t shift-left-antares-sandbox:bookworm .
```

Every command is streamed to the orchestrator twice: at dispatch (the command the model asked to run) and when execute returns (exit status and output). Both writes go through the redaction chokepoint (`antares.sandbox.command` plus the investigation trace row), authenticated with a short-lived `slat_…` callback (or a `slt_…` triage token). A crashed or hung `docker exec` therefore still leaves the dispatched command on disk.

Set `ANTARES_SANDBOX=subprocess` only for unit tests without Docker.

Cancel is checked at turn boundaries, not inside `generate()`. Worst case the current generation (up to `models.antares.stage_timeouts.generation`, default 300s) plus an in-flight `docker exec` (10s) runs after cancel.

## Memory

The model stays resident for one triage run, then unloads. Recycle the process after `ANTARES_RECYCLE_AFTER_RUNS` (default 10). Contract: [model-server-contract.md](model-server-contract.md).

Concurrent Antares-1B and Foundation-Sec Q4_K_M on 24 GB is tight; sequential load (`resident_for_run` / `on_demand`) is the default.

## HTTP surface (antares-server `:8090`)

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/triage/run` | Agent loop used by investigations |
| `POST /v1/completions` | OpenAI-compatible completions |
| `POST /v1/analyze` | Legacy diff-hunk JSON; not used for the merge gate |
| `POST /v1/unload` | Unload weights |

The official Antares CLI ZIP in the Hugging Face repo is unused by Shift-Left. Model weights are Apache-2.0; see [licensing.md](licensing.md).
