# System Health — Runtime Prerequisites Report

Date: 2026-08-30

## Complete derived prerequisite catalog

| ID | Name | Criticality | Source |
|----|------|-------------|--------|
| postgres | Postgres (Forgejo database) | CRITICAL | docker-compose.yml |
| forgejo | Forgejo git hosting | CRITICAL | docker-compose.yml |
| forgejo_token | FORGEJO_TOKEN scopes | CRITICAL | config schema + README |
| forgejo_runner | Forgejo Actions runner | CRITICAL | docker-compose.yml + workflows |
| git_backend | Git backend (non-sovereign) | CRITICAL | config schema |
| orchestrator_store | Orchestrator findings store | CRITICAL | config schema |
| policy_config | Policy rules loaded | CRITICAL | sovereignty/checks.py (derived) |
| foundation_sec_server | Foundation-Sec server + quant identity | DEGRADED_CONFIG | config + model server /health |
| foundation_sec_weights | Foundation-Sec GGUF SHA256 | DEGRADED_CONFIG | self-check.sh + shift_left_shared.weights |
| code_handlers | Code handler rules | DEGRADED_CODE | handlers/code/registry.py (derived) |
| antares_server | Antares server | ADVISORY | docker-compose.yml (optional profile) |
| antares_weights | Antares weights SHA256 | ADVISORY | self-check.sh |
| reference_cache | Reference data cache | ADVISORY | reference/cache.py |
| terraform_binary | Terraform binary + version | DEPLOYMENT | deployment.fmc (when enabled) |
| fmc_provider | FMC provider initialized | DEPLOYMENT | deployment.fmc (when enabled) |
| fmc_credentials | FMC credential env vars present | DEPLOYMENT | deployment.fmc (when enabled) |

**Not in original section 1 but derived from compose/config/self-check:**

- **policy_config** — fail-loud policy load at startup; without valid rules the gate cannot evaluate findings.
- **git_backend** — CRITICAL path when `git.backend` is not bundled-forgejo (external GitHub/GitLab).
- **orchestrator_store schema_version** — config `schema_version` must match `CURRENT_SCHEMA_VERSION` (7).

## Consolidation with existing self-check

| Existing | Reused in prerequisites |
|----------|-------------------------|
| `sovereignty/checks.check_policy_config` | `policy_config` check |
| `shift_left_shared.weights.verify_gguf_weight` | `foundation_sec_weights` |
| `shift_left_shared.weights.verify_antares_weights` | `antares_weights` (advisory) |
| `handlers/code/registry.validate_code_rules` | `code_handlers` |
| `system/models_inventory.foundation_sec_inventory` | weight staging details in failures |
| `system/diagnostics.diagnose_service_url_error` | Forgejo / Foundation-Sec errors |

Startup `/self-check` and `scripts/self-check.sh` remain separate operator tools; System view surfaces runtime functional checks with criticality-aware overall state.

## Overall state computation

- **FAILED** — any CRITICAL check failed or timed out (skipped dependents do not add independent failures).
- **DEGRADED** — all CRITICAL healthy, but DEGRADED_CONFIG and/or DEGRADED_CODE checks failed.
- **HEALTHY** — no CRITICAL or DEGRADED-class failures; ADVISORY and DEPLOYMENT failures are surfaced but do not change overall state.

Dependency attribution: when Postgres fails, Forgejo / token / runner checks are **skipped** (not reported as independent CRITICAL faults).

## Check execution discipline

- Per-check timeout: 3s default (`DEFAULT_CHECK_TIMEOUT_SECONDS`); timed-out checks report `status: timed_out`.
- Result cache: 30s TTL with `report_generated_at` shown in UI; `?refresh=true` bypasses cache.
- Health checks use GET `/health` only for model servers — no `/v1/analyze`, no inference, no egress (Antares uses direct httpx GET to configured URL only).

## API

- `GET /api/v1/system/status?refresh=false` — full system payload including `prerequisites` and `health`.
- `GET /api/v1/system/prerequisites?refresh=false` — structured prerequisite report only (scriptable monitoring).

## UI

Prerequisites grouped by criticality on `/ui/health`:

1. Critical — pipeline prerequisites
2. Degraded — config path
3. Degraded — code path
4. Advisory (does not change overall state)
5. Deployment (FMC enabled only)

Each failing row shows actual error text, affected capability, remediation, topology, last-checked timestamp, and Tier 4 service action button where applicable.

## Test results (observed)

```
47 passed — test_prerequisites_health, test_system_view, test_ui_phase4, test_ui_netsecops
12 passed — test_prerequisites_health alone
```

| Requirement | Test |
|-------------|------|
| Postgres down → FAILED; Forgejo skipped | `test_postgres_failure_yields_failed_and_skips_forgejo` |
| Foundation-Sec down → DEGRADED | `test_foundation_sec_failure_is_degraded_not_failed`, `test_unreachable_model_server_is_degraded` |
| Antares down → HEALTHY overall | `test_antares_advisory_failure_does_not_degrade` |
| Invalid FORGEJO_TOKEN CRITICAL | `test_invalid_forgejo_token_critical` |
| Offline runner detected | `test_offline_runner_detected` |
| Runner label mismatch | `test_runner_label_mismatch_detected` |
| SHA256 mismatch | `test_sha256_mismatch_degraded_config` |
| Unexpected quant | `test_unexpected_quant_degraded` |
| No model load/inference | `test_health_checks_do_not_load_models` |
| Hung check times out | `test_hung_check_times_out` |
