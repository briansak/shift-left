# Antares Triage + Deterministic Rule Corpus — Integration Report

**Date:** 2026-08-24  
**Scope:** Items 1–4 of revised Antares integration (Phase 4 not started; unseen corpus not re-run).

---

## 1. CWE source model (decided)

| Mode | Status | Notes |
|------|--------|-------|
| **Operator-supplied CWE** | Primary | `POST /api/v1/triage/antares` with `task_cwe` |
| **CVE → CWE via local cache** | Supported | `advisory_cve` resolves through `ReferenceDataCache`; fails closed if absent |
| **Configured scheduled CWE set** | Config stub | `antares_triage.scheduled_cwes` — empty by default; latency ~35–90 s × N |
| **Automatic CWE nomination from diff** | **Not implemented** | Feasible later via path/glob → handler rule mapping (same as code/config handlers); out of scope this pass |

Implementation: `services/orchestrator/shift_left/triage/service.py`

---

## 2. Antares as advisory triage (not PR gate)

- Removed from `ReviewService` code path; PR code gate uses `findings_from_code_handlers()` only.
- New record type: `LocalizationResult` (schema v7) — structurally advisory; forbidden in policy rules at load time.
- Triage API: `POST /api/v1/triage/antares`
- Agent loop: `/v1/triage/run` with read-only sandbox, 15 turns max, temperature 0.3, top_p 1.0.
- OpenAI-compatible `/v1/completions` added alongside legacy `/v1/analyze`.
- Model server contract: [docs/model-server-contract.md](../docs/model-server-contract.md)
- Operator docs: [docs/antares-triage.md](../docs/antares-triage.md)

### Published File F1 (surfaced with results)

| Variant | File F1 | Triage support |
|---------|---------|----------------|
| 350M | 0.135 | Rejected when `minimum_variant: 1b` |
| 1B | 0.209 | **Minimum staged variant** |
| 3B | 0.223 | Optional future staging |

---

## 3. Memory — Antares 1B and 24 GB coexistence

### Measured (350M on host-native server, prior validation)

From `validation/reports/memory-cycles-report.json` (350M, on_demand analyze cycles):

| Metric | Value |
|--------|-------|
| Peak RSS (350M, single analyze) | ~245–346 MiB |
| After-unload RSS growth | 349 → 749 MiB over 10 cycles (~25 MiB/cycle) |
| Per-run unload | 4 ms wall |

### Antares 1B — not re-measured this pass

**TODO:** Stage `fdtn-ai/antares-1b` under `models/1b`, record SHA256 in prewarm manifest, run `scripts/validate-peak-memory.py` with `resident_for_run`.

**Planning estimate (not measured):** 1B weights are ~3× 350M parameters; expect roughly **0.8–1.5 GB peak RSS** resident across triage turns (order-of-magnitude).

### Foundation-Sec Q4_K_M @ n_ctx 4096 (recommended)

From remediation planning: ~**5.4 GB** model footprint (vs ~9.3 GB for Q8 @ 8192).

### 24 GB coexistence assessment

| Scenario | Fits 24 GB? |
|----------|-------------|
| Sequential: Antares triage run → unload → Foundation-Sec on_demand review | **Yes** (recommended) |
| Concurrent resident Antares 1B + Foundation-Sec Q4 loaded | **Marginal / likely no** without swap |
| Concurrent Antares 1B + Foundation-Sec Q8 @ 8192 | **No** (prior swap observed) |

**Recycle:** `ANTARES_RECYCLE_AFTER_RUNS=10` (default) logs recycle recommendation after N triage runs; leak persists per run cycle on MPS — process restart required, not per-request unload alone.

---

## 4. CLI license determination

| Artifact | License | Redistribution |
|----------|---------|----------------|
| Antares model weights (1B) | Apache-2.0 (HF model card) | Permitted with NOTICE |
| Antares CLI ZIP (bundled in HF 1B repo) | **UNVERIFIED** | **Blocks Phase 6 bundling until confirmed** |

**TODO:** Download CLI ZIP from `fdtn-ai/antares-1b` Files on a connected host; inspect `LICENSE` / `NOTICE` separately from model weights.

Subprocess integration deferred until license verified. In-repo agent loop implements equivalent protocol.

---

## 5. Deterministic rule corpus — unclassified rate

Report script: `scripts/report-handler-cwe-coverage.py`  
Output: `validation/reports/handler-cwe-coverage.json`

| Metric | Before | After |
|--------|--------|-------|
| Total entries (fixtures + corpus) | 16 | 16 |
| Handler-classified | 4 | **7** |
| Unclassified | 12 | **9** |
| Unclassified rate | **75.0%** | **56.2%** |

### Corpus bad-case coverage (policy-relevant)

All **5/5** `expect_flagged: true` corpus entries now receive `handler_asserted_cwe`:

| Corpus path | Rule | CWE |
|-------------|------|-----|
| `bad/terraform-open-sg.tf` | `terraform/sg-global-ingress` | CWE-284 |
| `bad/k8s-hostnetwork.yaml` | `kubernetes/hostnetwork` | CWE-250 |
| `bad/ansible-wildcard-sudo.yml` | `ansible/wildcard-sudo` | CWE-269 |
| `bad/firewall-any-any.rules` | `firewall/permissive-any-any` | CWE-284 |
| `bad/nginx-no-tls.conf` | `nginx/plaintext-listener` | CWE-319 |

Remaining 9 unclassified entries are **negative controls** (clean + messy fixtures) — intentional non-matches.

### Policy meaningfulness

**Yes, for the exercised weakness classes.** Rules such as `block-critical-code` / severity-threshold policies can now fire deterministically when PRs touch ASA any/any, open SG ingress, hostNetwork, wildcard sudo, or plaintext nginx listeners.

**Still limited** for messy/legacy patterns (verbose ACL prose, commented terraform blocks) — by design (high-precision intent). Additional rules would be needed for those classes.

### Per-rule precision (corpus negatives as FP pool)

| Rule | TP | FP | Precision | False positives |
|------|----|----|-----------|-----------------|
| `firewall/permissive-any-any` | 1 | 0 | 1.0 | — |
| `terraform/sg-global-ingress` | 1 | 0 | 1.0 | — |
| `kubernetes/hostnetwork` | 1 | 0 | 1.0 | — |
| `ansible/wildcard-sudo` | 1 | 0 | 1.0 | — |
| `nginx/plaintext-listener` | 1 | 0 | 1.0 | — |
| `network/global-cidr-allow` | 0 | 0 | n/a | (no dedicated positive in corpus) |

No individual false positives observed.

### Fix applied

Glob matcher corrected so `**/deploy/**` and `**/k8s/**` match root-anchored paths (`deploy/...`, `k8s/...`).

---

## 6. Code-path gate (deterministic)

Pluggable rules: `services/orchestrator/shift_left/handlers/code/registry.py`

Initial high-precision Python rules: CWE-89 (SQLi f-string), CWE-798 (hardcoded secret), CWE-22 (path traversal), CWE-78 (os.system).

Findings use `FindingSource.CODE_HANDLER`, include `line_range`, `handler_asserted_cwe` from matched rule only.

Foundation-Sec enrichment failure does not affect gate decision (existing fail-closed analysis tests retained).

---

## 7. Test results (observed)

```
116 passed, 1 warning in 4.07s
```

| Area | Result |
|------|--------|
| Sandbox refuses write | Pass (`test_sandbox_refuses_write_attempt`) |
| Sandbox refuses network | Pass (`test_sandbox_refuses_network_attempt`) |
| Sandbox refuses repo code execution | Pass (`test_sandbox_refuses_execute_repository_code`) |
| `submit_no_vulnerability_found` ≠ failed | Pass (`test_submit_no_vulnerability_not_marked_failed`) |
| `LocalizationResult` fields forbidden in policy | Pass (`test_localization_fields_forbidden_in_policy_rules`) |
| Prohibited detection wording absent | Pass (`test_prohibited_wording_absent_from_triage_summary`) |
| Model unload + recycle after N runs | Pass (`test_unload_after_run_increments_counter_and_recycles`) |
| Identical code → identical findings | Pass (code handler integration tests) |
| Code findings include `line_range` | Pass (`test_code_findings_include_line_range`) |
| CWE catalog validation at load | Pass (handler + policy tests) |

---

## 8. Documentation corrections

| Location | Change |
|----------|--------|
| `README.md` | Antares repositioned as advisory triage; PR code gate = deterministic handlers |
| `docs/architecture.md` | Removed “diff-hunk Antares for E2E”; added LocalizationResult + triage split |
| `docs/antares-triage.md` | **New** — invocation, F1, sandbox, never-gates statement |
| `docs/model-server-contract.md` | **New** — versioned v1 contract |
| `config/shift-left.example.yaml` | Schema 7, `antares_triage` section, expanded CWE severity map |

Grep sweep: removed/updated claims that Antares detects vulnerabilities, produces line numbers, or gates PRs in primary docs.

---

## 9. Constraints preserved

- Local-only inference, no telemetry, no runtime egress
- Findings advisory only; human-in-the-loop mandatory
- Defensive scope only — no exploitation or attack simulation
- Unseen corpus **not** re-run (per instruction)

---

## 10. Remaining TODOs

1. Stage Antares-1B weights + SHA256 in prewarm manifest
2. Measure 1B peak RSS with `resident_for_run` triage protocol
3. Verify Antares CLI ZIP license separately from weights
4. Optional: `shift-left antares-triage` CLI wrapper
5. Optional: scheduled CWE sweep operator command
