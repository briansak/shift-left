# NetSecOps UI Redesign — Integration Report

**Date:** 2026-08-30  
**Scope:** Phase 4 IA inversion + plan-only Phase 5 slice (no apply, Antares triage untouched)

## Test results (observed)

```
35 passed (test_ui_netsecops.py, test_ui_phase4.py, test_config_schema.py, test_approval_gating.py)
```

Environment: Python 3.12 venv, `services/orchestrator`, pytest 8.x.

| Requirement | Result |
|-------------|--------|
| Change state server-computed | PASS — `GET /api/v1/changes/{owner}/{repo}/{pr_number}/state` |
| New commit → validating; invalidates approval + plan | PASS |
| Plan endpoint refuses SHA without allowing gate | PASS — HTTP 403 |
| Plan requires `deploy`; `approve` alone insufficient | PASS — HTTP 403 |
| `rbac.allow_self_approval=false` → self-approval refused at API | PASS — HTTP 400 |
| `rbac.allow_self_approval=true` → banner + audit `self_approval_permitted` | PASS |
| FMC credentials absent from plan output / API | PASS — `[REDACTED]` in output |
| No `terraform apply` code path | PASS — deployment module plan-only |
| Unclassified severity distinct from low | PASS — `.severity-unclassified` |
| FAILED validation → validation incomplete UI | PASS |
| Declared-state limitation notice in diff zone | PASS |
| New UI routes load with egress blocked | PASS |

## New API endpoints

| Method | Path | Capability | Purpose |
|--------|------|------------|---------|
| `GET` | `/api/v1/changes` | auth | List in-flight config changes with server-computed state |
| `GET` | `/api/v1/changes/{owner}/{repo}/{pr_number}/state` | auth | Change workflow state + reason + next action |
| `POST` | `/api/v1/changes/{owner}/{repo}/{pr_number}/plan` | `deploy` | Generate/store Terraform plan (gate checked server-side) |

Existing endpoints extended: gate response includes `rbac_allow_self_approval`; approval audit includes `self_approval_permitted`.

## Change state model (server-computed)

States in `ChangeState` enum (`shift_left/models/schema.py`):

| State | Meaning |
|-------|---------|
| `draft/open` | No validation recorded |
| `validating` | Head SHA changed or policy not bound to head |
| `validation_incomplete` | Analysis failed / gate `analysis_incomplete` |
| `blocked_by_policy` | Policy or gate block without approval path |
| `awaiting_approval` | Gate requires human approval for current SHA |
| `approved` | Gate allowing; no plan for current SHA |
| `plan_generated` | Fresh plan stored for current SHA |
| `plan_stale` | Plan exists for older SHA |
| `deployed` | Reserved (unused this pass) |

Transitions audited via `change.state_transition` (review complete, approval, plan, new commit).

## UI changes

- Landing: `/ui/` → `/ui/changes` (Config changes queue)
- Nav order: Config changes → Findings → Policy → Audit → System → Antares triage
- Change detail (`/ui/pr/...`): four zones — current vs proposed (declared-state notice), validation, gate/approval, plan-only deployment with disabled Apply
- Persistent banner when `rbac.allow_self_approval=true`
- System view: RBAC flag + egress path table (FMC management plane row)

## Capabilities

- New token capability: `deploy` (separate from `approve`)
- Plan generation (UI + API) requires `deploy`
- `rbac.allow_self_approval` (default `false`): dev-only SoD bypass with startup log warning, audit on each self-approval, System/gate surfacing

## Plan-only deployment backend

- `shift_left/deployment/terraform_plan.py` — local `terraform init` + `terraform plan -detailed-exitcode`
- `shift_left/deployment/service.py` — gate check before plan; credentials from env only; output sanitized
- Plans persisted in SQLite (`terraform_plans` table via `PlanStore`)
- Audited: `deployment.plan_generated`, `deployment.plan_invalidated`

## Dependencies added

**None.** Uses existing stdlib `asyncio.subprocess`, SQLAlchemy, FastAPI, Jinja2.

## FMC lab verification TODOs

1. Confirm `terraform` + CiscoDevNet/fmc provider versions against lab FMC (`deployment/terraform_plan.py`, `config/shift-left.example.yaml`).
2. Confirm `terraform init` backend/provider lock for `examples/ftdv-firewall/terraform`.
3. Set `deployment.fmc.enabled: true`, credential env vars, and `allowed_endpoint` for FMC management host:port in sovereignty docs.
4. Validate plan output parsing (`Plan: N to add, …`) matches your provider’s CLI format.

## Sovereignty

- UI remains loopback-oriented; no external assets
- FMC path documented as in-org management plane (not public internet egress) in System view egress table
- `terraform apply` intentionally not implemented

## Constraints carried forward

Local-only inference, no telemetry, advisory findings where marked, human-in-the-loop mandatory, defensive scope only.
