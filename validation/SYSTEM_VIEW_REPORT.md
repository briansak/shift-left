# System View — Operational Controls Report

Date: 2026-08-30

## Defect root causes (original three)

### 1. Foundation-Sec `[Errno 8] nodename nor servname provided`

**Root cause:** DNS resolution failure, not inference failure. The default configured URL is `http://foundation-sec-server:8091`, which resolves only inside Docker Compose. When the orchestrator runs host-native (e.g. `scripts/start-orchestrator-local.sh`), that hostname is not in `/etc/hosts` and fails with errno 8.

**Fix / operator action:**
- Host-native orchestrator: set `FOUNDATION_SEC_SERVICE_URL=http://127.0.0.1:8091` (or `models.foundation_sec.service_url`) and start Foundation-Sec locally.
- Docker orchestrator with host-native Foundation-Sec: `FOUNDATION_SEC_SERVICE_URL=http://host.docker.internal:8091`.
- Docker orchestrator with containerized Foundation-Sec: `docker compose --profile linux-cpu up -d foundation-sec-server`.

**UI behavior:** Unreachable Foundation-Sec now drives server-computed overall state **DEGRADED** with a named condition (`foundation_sec_unreachable`) and an actionable diagnosis panel — not a raw JSON blob under “System health”.

### 2. Running config Q8_0 / n_ctx=8192 vs recommended Q4_K_M / n_ctx=4096

| Question | Answer |
|----------|--------|
| Is Q4_K_M staged? | **No.** Only `models/foundation-sec-q8_0/` contains weights (`foundation-sec-1.1-8b-instruct-q8_0.gguf`). `models/foundation-sec-q4_k_m/` is absent. |
| Is recommended config applied? | **Partially.** Code default for `models.foundation_sec.max_context_tokens` is **4096**; `use_low_memory` defaults **false** (Q8_0). A running profile of Q8_0 at n_ctx=8192 indicates operator `config/shift-left.yaml` and/or Compose env (`FOUNDATION_SEC_N_CTX:-8192`) overriding defaults — not the recommended low-memory profile. |
| System view surfacing | Inventory + degrading condition `foundation_sec_high_memory_profile` when Q8_0 is staged, `use_low_memory=false`, and n_ctx > 4096. Tier 3 controls allow switching quant/n_ctx with explicit restart guidance. |

### 3. `newest ingested lastModified: unknown`

**Root cause:** Manifest field was never written on older syncs.

**Fix:** `ReferenceDataCache.cache_status()` derives `newest_last_modified` by scanning ingested `reference-data/cve/*.json` for `lastModified` when the manifest field is absent. Source is reported as `derived_from_cve_cache` vs `manifest`.

---

## Settings tiers (implemented)

| Tier | Settings | Mutability | Enforcement |
|------|----------|------------|-------------|
| 1 | `sovereignty.deny_egress`, `sovereignty.runtime_allowed_endpoints` | Read-only in UI/API | `IMMUTABLE_CONFIG_PATHS`; `/api/v1/system/settings/immutable-probe` returns 403 |
| 2 | `rbac.allow_self_approval` | Admin + typed phrase | `ENABLE SELF APPROVAL` / `DISABLE SELF APPROVAL`; audited |
| 3 | Foundation-Sec quant/n_ctx/load, Antares load/recycle, enrichment flags | Admin, schema-validated, audited | Writes to `config/shift-left.yaml` via ruamel.yaml (comments preserved), reload in-process |
| 4 | Named service actions only | Admin, audited | Hardcoded argv maps; no client command strings |

---

## Config persistence model

- Runtime Tier 2/3 changes write **`config/shift-left.yaml`** (comment-preserving `ruamel.yaml`), validate against the same schema as startup, then reload orchestrator config in-process.
- Drift banner when on-disk file changes outside the System view since process start.
- Secrets/credentials are not writable through this path.

**New dependency:** `ruamel.yaml>=0.18.0` (comment-preserving YAML; no new runtime services).

---

## Service lifecycle (Tier 4)

Fixed service set: `foundation-sec-server`, `antares-server`, `orchestrator`, `forgejo`, `postgres`.

Topology-aware controls via `SHIFT_LEFT_SERVICE_TOPOLOGY=host-native|docker-compose` (auto-detected: `/.dockerenv` → compose, else host-native):

- **host-native:** Apple Silicon Antares / Foundation-Sec via `python -m …_server.main`; stop via `pkill -f …`.
- **docker-compose:** `docker compose` up/stop/restart for named services.

Live status: running (health URL), PID, RSS, runtime JSON where available, per-service errors.

---

## System view layout (`/ui/health`)

1. **Status** — healthy / degraded / failed + named conditions + Foundation-Sec diagnosis
2. **Services** — live status + lifecycle buttons (admin only)
3. **Model configuration** — Tier 3 form + inventory/measured memory note
4. **Security controls** — Tier 1 read-only, Tier 2 typed confirmation
5. **Reference data** — present/stale/sync/newest lastModified + seed/NVD sync (NVD labeled operator-initiated egress)
6. **Network paths** — existing egress path table + probe status

Capability-aware: controls hidden without `admin`; API returns 403 when invoked directly.

---

## Test results (observed)

```
54 passed (test_system_view, test_ui_phase4, test_ui_netsecops, test_phase3_hardening, test_approval_gating)
11 passed (test_system_view alone)
```

| Requirement | Test |
|-------------|------|
| No API path modifies deny_egress / egress probe | `test_immutable_sovereignty_settings_refused` |
| allow_self_approval requires admin + typed confirmation | `test_rbac_self_approval_requires_confirmation` |
| Enable/disable allow_self_approval audited with actor | `test_rbac_self_approval_requires_confirmation`, `test_rbac_disable_writes_audit` |
| Tier 3 schema validation rejects invalid values | `test_tier3_invalid_value_rejected` |
| Config writes preserve comments + reload validate | `test_config_write_preserves_comments_and_reloads` |
| Settings writes audited old/new | `test_config_write_preserves_comments_and_reloads` |
| No client string reaches subprocess | `test_no_client_string_in_subprocess` |
| Service actions require admin | `test_service_action_requires_admin` |
| Unreachable model server → DEGRADED | `test_unreachable_model_server_is_degraded` |
| New routes load with egress blocked | `test_system_routes_egress_blocked` |

---

## Sovereignty / Antares constraints preserved

- Loopback bind, zero external assets, no telemetry, no client-side error reporting unchanged.
- Antares triage view not modified.
- Egress-blocked route tests extended for `/ui/health` and `/api/v1/system/status`.
