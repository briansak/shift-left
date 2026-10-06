# Service Lifecycle Verification Report

Verified start with dependency ordering for the System health view.

## Post-action verification

After `start` or `restart`, the lifecycle manager polls the mapped prerequisite check (not command exit code alone):

| Outcome | Meaning |
|---------|---------|
| `command_failed` | Hardcoded argv dispatch failed |
| `verification_timeout` | Command succeeded but prerequisite never became healthy within per-service timeout |
| `verified_healthy` | Prerequisite check passed after bounded polling |

Progress phases recorded in `verification.progress`: `starting` → `waiting_for_readiness` (with elapsed ms) → `verified_healthy` or `verification_timeout`.

**Audit:** two events per verified start/restart:

- `service.lifecycle.command` — argv dispatched, command outcome
- `service.lifecycle.verified` — command + verification outcomes and progress

**Default readiness timeouts (seconds):** postgres 90, forgejo 120, forgejo-runner 90, foundation-sec 45, antares 60, orchestrator 60. Polling uses 0.5s initial delay, 1.5× backoff, 5s cap.

## Dependency ordering

Explicit graph (`shift_left/system/service_dependencies.py`):

```
postgres → (none)
forgejo → postgres
forgejo-runner → postgres, forgejo
orchestrator → postgres, forgejo
foundation-sec-server, antares-server → (none)
```

**Start-all chain:** postgres → forgejo → forgejo-runner (+ foundation-sec-server when enabled and `include_degraded=true`).

- Each step waits for verified health before the next.
- Failure stops the chain; `failed_service` and `failed_phase` identify the broken link.
- Individual start with unhealthy dependency raises upfront (dependency named, not downstream fault).
- `start_dependency_chain` / UI **start chain** runs start-all when dependencies block.

## Readiness verification by topology

| Service | Compose | Host-native orchestrator |
|---------|---------|---------------------------|
| postgres, forgejo, forgejo-runner | `docker compose up` + TCP/API/runner checks | Same via hardcoded `docker compose` CLI when Docker available |
| foundation-sec, antares | Compose profile when in-container | Local `python -m …main` on Apple Silicon; readiness via GET `/health` only |
| orchestrator | detect-only | detect-only (cannot self-restart) |

Readiness polling calls `PrerequisiteChecker.verify_check()` — functional checks (Postgres TCP, Forgejo API, runner registration, `/health`). No analyze/inference/egress.

## UI

- **Start all prerequisites** (admin, when overall state is failed/degraded)
- Per-service actions when `start_feasibility == start`
- **start chain** when dependencies exist but direct start is blocked
- Dependency graph and feasibility notes in Services table
- Outcome banners after actions (`service-action`, `start-all` query params)

## API

- `POST /api/v1/system/services/action` — returns `command_outcome`, `verification_outcome`, `verification.progress`
- `POST /api/v1/system/services/start-all` — ordered chain with `steps[]`
- `GET /api/v1/system/status` — includes `dependency_graph`

## Test results

```
31 passed (test_service_lifecycle_verification + test_system_view + test_prerequisites_health + test_ui_phase4 + test_ui_netsecops)
```

Coverage:

| Scenario | Result |
|----------|--------|
| Start with postgres down → forgejo blocked, postgres named | PASS |
| Start-all stops at failed postgres verification, no downstream starts | PASS |
| Start-all order postgres → forgejo → forgejo-runner | PASS |
| Command ok + verification timeout → not success | PASS |
| Audit: `service.lifecycle.command` vs `service.lifecycle.verified` | PASS |
| Readiness polling does not invoke analyze | PASS |
| Orchestrator detect-only | PASS |
| Host-native model feasibility notes GET /health only | PASS |
