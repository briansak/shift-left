# Phase 4 — Local Web UI Report

**Date:** 2026-08-24

## Framework choice

**Server-rendered Jinja2 templates + vendored CSS/vanilla JS** (no React/Vue/npm build).

| Criterion | Decision |
|-----------|----------|
| Dependency footprint | **+1 runtime dep:** `jinja2` (already standard with Starlette). **0 npm packages.** |
| Auditability | HTML templates and static assets live in-repo; no minified third-party bundles. |
| Sovereignty | No CDN, no external fonts, no client telemetry hooks. |
| Logic boundary | All review/policy/severity/model logic stays in existing Python services; UI calls APIs or server handlers only. |

SPA rejected: would add a build toolchain, transitive npm supply-chain surface, and tempt client-side policy derivation.

## Added dependencies

| Package | Purpose |
|---------|---------|
| `jinja2>=3.1.4` | Server-side HTML rendering |

**Total new runtime dependencies: 1**

## API endpoints added (avoid client-side computation)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/me` | Token-derived actor + capabilities |
| `GET /api/v1/findings` | Filtered findings list (repo, pr_ref, target_kind, policy_severity, status, source) |
| `GET /api/v1/pr/{owner}/{repo}/{pr_number}/context` | PR bundle: findings, policy, gate, approvals, diff file views |
| `GET /api/v1/approvals/{owner}/{repo}/{pr_number}` | Approval history |
| `GET /api/v1/system/status` | Extended health + sovereignty + model config for UI |

## UI routes

| Route | View |
|-------|------|
| `/ui/login` | Token sign-in (HttpOnly cookie) |
| `/ui/findings` | Findings dashboard |
| `/ui/pr/{owner}/{repo}/{pr_number}` | PR review (zones A/B/C + diff viewer) |
| `/ui/policy` | Read-only policy |
| `/ui/audit` | Read-only audit + export link |
| `/ui/health` | System health |
| `/ui/triage` | Antares advisory triage |

## Sovereignty controls

- Orchestrator default bind: **`127.0.0.1`** (`config/shift-left.example.yaml`)
- Startup refuses non-loopback bind when UI enabled unless `ALLOW_NON_LOOPBACK_UI=true`
- `ui.require_loopback_client` restricts UI to loopback clients (disable in tests only)
- `scripts/check-ui-assets.py` — build-time scan for external asset URLs
- Static assets: `/ui/static/styles.css`, `/ui/static/app.js` only

## Test results (observed)

```
services/orchestrator/tests/: 96 passed
services/antares-server/tests/: 18 passed
services/foundation-sec-server/tests/: 13 passed
Total: 127 passed
```

Phase 4 UI tests (`test_ui_phase4.py`): **12 passed**

| Requirement | Result |
|-------------|--------|
| All UI routes load with egress blocked | Pass (socket + egress probe patched) |
| External asset scan clean | Pass |
| Capability hidden + API rejects | Pass |
| Triage prohibited wording absent | Pass |
| Verdict prohibited wording stripped in zone C | Pass |
| FAILED analysis → “Analysis incomplete” | Pass |
| Invalidated approval shown | Pass |
| Self-approval control unavailable | Pass |
| Rationale required for FP / accepted_risk | Pass |
| No audit delete affordance | Pass |
| Audit export with egress blocked | Pass |
| Stale cache surfaced on findings | Pass |

## Docker note

Compose deployments that bind `0.0.0.0` must set `ALLOW_NON_LOOPBACK_UI=true` explicitly — documented in example config comment.

## Documentation

- `config/shift-left.example.yaml` — `ui` section
- Phase roadmap in README updated to mark Phase 4 UI
