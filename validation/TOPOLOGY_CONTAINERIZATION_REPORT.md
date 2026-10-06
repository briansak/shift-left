# Topology, Containerization, and Configurable Paths Report

## Root cause: topology contradiction

**What was wrong:** A single `topology()` label (`host-native` vs `docker-compose`) was derived only from `/.dockerenv`. On a host-native orchestrator with Colima/Docker installed, the label was `host-native` while:

- Service URLs and git config pointed at Compose DNS names (`postgres`, `foundation-sec-server`, `forgejo`)
- Service control used `docker compose` CLI (`control_mode: docker-compose-via-cli`)
- Postgres remediation referenced "host-native orchestrator reachability" while checks connected to `postgres:5432`

Those hostnames resolve only on the `sovereign_internal` Compose network, causing errno-8 style failures on the host.

**Fix:** Observable multi-signal detection in `shift_left/system/topology.py`:

| Signal | Purpose |
|--------|---------|
| `/.dockerenv` + cgroup | orchestrator in container |
| DNS probe for `postgres` | on Compose network |
| `/var/run/docker.sock` | lifecycle control available |
| `ANTARES_SERVICE_URL` / `FOUNDATION_SEC_SERVICE_URL` | model hosting mode |

The System view now reports `topology_report` with `service_control_mode`, `model_hosting`, `prior_mismatch` notes, and `detection_notes`.

## Target topology

| Component | Placement |
|-----------|-----------|
| postgres, forgejo, forgejo-runner, orchestrator | Compose (`sovereign_internal` + edge for orchestrator) |
| antares-server, foundation-sec-server (macOS) | Host-native; reached via `host.docker.internal:8090/8091` |
| antares-server, foundation-sec-server (Linux) | Compose profiles `linux-cpu` / `linux-gpu` |

**Docker socket:** mounted into orchestrator with explicit UI warning (privilege escalation). Actions remain the fixed named set only.

**detect_only cases (after change):**

1. **Orchestrator self-restart** — always detect-only
2. **macOS host-native model servers** when orchestrator runs in Compose — instruct to start on host
3. **Compose services** when Docker socket or Compose CLI unavailable — detect-only with actionable error

## Compose CLI detection

Probed at startup (cached): `docker compose` first, then `docker-compose`. Override via `orchestrator.compose_command` or `SHIFT_LEFT_COMPOSE_COMMAND`. Reported in System view as `compose_cli.form`. Neither form is hardcoded in service argv builders — all use `compose_argv_prefix()`.

## Tier 3 configurable paths (admin, audited)

- Model weights paths (Antares, Foundation-Sec Q8_0, Q4_K_M)
- Model service URLs (allowlist validated on submit)
- Reference cache directory, findings SQLite path
- Q4_K_M profile blocked until weights staged and SHA256 verified
- Staging command shown: `hf download fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF --local-dir models/foundation-sec-q4_k_m`

## Other fixes

- **newest_last_modified:** derives from CVE cache when manifest field absent; UI explains when unavailable (empty/missing cve dir)
- **Egress probe UI:** distinguishes `skipped_connected_dev`, `disabled`, `blocked`, `unexpected_allow`, `not_run`

## Verified start (Compose)

Unchanged behavior, now achievable with Docker socket: postgres → forgejo → forgejo-runner, per-service verification, separate audit events.

## Test results (actual)

```
70 passed (topology+tier3, lifecycle, system, prerequisites, network boundary, ui_phase4, ui_netsecops)
```

| Test | Result |
|------|--------|
| Topology host-native vs compose container | PASS |
| Compose CLI both forms + override | PASS |
| Service URL outside allowlist rejected | PASS |
| Q4_K_M blocked when unstaged | PASS |
| Start-all dependency order + verification | PASS |
| Network boundary (host.docker.internal ports) | PASS |
| No client strings in subprocess | PASS |

## Detected compose form (this host)

Auto-detected at test runtime via `_probe_form` mocks and live Colima environment where Docker plugin is available: **`docker compose`** (plugin preferred when both work).
