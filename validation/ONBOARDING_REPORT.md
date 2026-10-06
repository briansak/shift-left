# Onboarding & Usability Overhaul — Validation Report

Date: 2026-08-30

## Target experience

```bash
git clone <repo> && cd shift-left && ./shift-left up
```

Single operator-initiated command; idempotent; resumable via re-run after failure or interrupt.

## Manual steps remaining on first run

| Before | After |
|--------|-------|
| ~15 steps across 3 terminals | **1 command** (`./shift-left up`) |

Optional follow-ups (not required for HEALTHY core pipeline):

- `./shift-left install-antares` — only if advisory triage is desired (HF terms + `HF_TOKEN`)
- `./shift-left token mint …` — only if bootstrap did not mint operator token (orchestrator DB not ready during forgejo phase)
- `./shift-left model …` — when orchestrator runs **in Docker** on Apple Silicon (UI lifecycle is detect-only; host CLI owns PIDs)

## Implemented CLI surface

| Command | Purpose |
|---------|---------|
| `./shift-left up` | 8-phase bootstrap: preflight → fetch → configure → start → forgejo → sample → verify → open browser |
| `./shift-left down` | Stop supervised model servers + Compose stack |
| `./shift-left status` | Prerequisite report (via orchestrator API when up) |
| `./shift-left doctor` | Preflight + compose + config presence |
| `./shift-left reset --confirm 'DESTROY SHIFT-LEFT LOCAL STATE'` | Wipe local state |
| `./shift-left install-antares` | Optional gated Antares weights |
| `./shift-left model start\|stop\|restart <service>` | Host-native model supervisor |
| `./shift-left new-repo <name>` | Local scaffold with workflow template |
| `./shift-left import-config <path>` | Reports matched vs out-of-glob files |

## Scope reduction

- **Antares optional by default** — `models.antares.installed` / `antares_triage.installed` default `false`; no `HF_TOKEN` on default `up`.
- Prerequisites report `not_installed` (advisory, OK) when Antares absent — overall state stays **HEALTHY**.
- **Foundation-Sec default Q4_K_M @ n_ctx 4096** — `use_low_memory: true` in example config and `generate_config()`.

## Test results (observed)

```text
PYTHONPATH=cli:orchestrator:shared pytest services/orchestrator/tests/
159 passed, 1 skipped, 1 warning
```

Included suites:

- `tests/test_onboarding.py` — phase resume, configure defaults, import-config globs, compose CLI forms, Forgejo secret idempotency, Antares not_installed → HEALTHY
- `tests/test_orchestrator_network_boundary.py` — **unchanged, passing** (runtime egress blocked)
- `tests/test_prerequisites_health.py`, `tests/test_service_lifecycle_verification.py`, full orchestrator suite

Skipped: `test_config_write_preserves_comments_and_reloads` when `ruamel.yaml` is not installed in the local venv (declared in `pyproject.toml`).

**Not run in CI (requires Docker + network):** full end-to-end `./shift-left up` from clean checkout through sample PR review in Config changes queue. Unit/integration coverage exercises individual phases and idempotency markers.

## detect_only after supervisor work

| Service | When detect_only | Why |
|---------|------------------|-----|
| `orchestrator` | Always | Cannot restart self from UI |
| `foundation-sec-server`, `antares-server` | macOS + orchestrator **in container** | Host PIDs not controllable from container namespace — use `./shift-left model …` on host |
| Compose services | Docker socket / CLI unavailable | Documented privilege grant |

When orchestrator runs **host-native**, model servers use supervised start/stop/restart (`.shift-left/supervisor.json`).

## Forgejo 11.x — verify before production

TODO markers in `cli/shift_left_cli/forgejo_bootstrap.py`:

- `forgejo admin user create` flags (`--must-change-password`, email)
- `forgejo admin user generate-access-token` scopes (`--scopes all`)
- Sample repo branch/contents API (`sample_repo.py`) — branch create fallback via `git/refs`
- Enable Actions via API if not default on fresh Forgejo 11.x install

Runner label enforced: `self-hosted:host` (must match workflow template).

## Constraints verified

- Secrets in `.env` only — `generate_env()`; not written to `shift-left.yaml`
- No update check in `./shift-left up`
- Runtime egress tests unchanged
- Service actions remain fixed named set

## Files added / key paths

- `./shift-left` → `scripts/shift-left`
- `cli/shift_left_cli/{up,down,status_cmd,doctor,reset,model_cmd,install_antares,repos}.py`
- `cli/shift_left_cli/{preflight,configure,fetch_phase,stack,forgejo_bootstrap,sample_repo,state,compose_util}.py`
- `services/orchestrator/shift_left/system/supervisor.py`
- UI: first-run banner, Antares not installed, Q8_0 memory warning, changes empty state
