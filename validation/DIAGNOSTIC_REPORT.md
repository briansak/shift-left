# Real-Inference Validation Diagnostic Report

**Date:** 2026-08-24  
**Scope:** Items 1–6 from diagnostic pass (Phase 4 not started)  
**Constraint:** No fixture/prompt tuning to improve confusion matrix scores; handler routing/context fixes only where noted.

---

## Retracted conclusions (unsupported by prior measurement)

| Prior claim | Why retracted |
|-------------|---------------|
| Combined peak RSS ~478 MiB; allocator retained ~257 MiB | Measured `RUSAGE_SELF` on the validation script, not model server PIDs. Physically impossible for 8B Q8_0 GGUF. |
| Antares returned 0 findings on SQLi diff = poor detection | **Invalid** while forward pass emitted `!` tokens (MPS float16 NaN logits) or malformed JSON. No detection-quality conclusion supported. |
| verify-runtime --real passed with real inference | Egress **startup probe was skipped** (`SHIFT_LEFT_SKIP_EGRESS_PROBE=1`); only EgressGuard external-block checks ran. |
| Foundation-Sec corpus confusion matrix (tp=2, tn=5, fp=2, fn=3) | Partially valid for Foundation-Sec only; Antares leg invalid; handler mis-routing (Ansible→Kubernetes) invalidated some paths. Re-run corpus after items 1–3 + handler fixes. |

---

## 1. Antares produced no valid output (highest priority)

### Root cause (evidence)

Diagnostic run on the peak-memory SQLi prompt (`models/350m`, GraniteMoeHybrid, staged SHA256 verified, `fdtn-ai/antares-350m`):

| Config | NaN/inf in last logits | First 4 decoded tokens |
|--------|------------------------|-------------------------|
| **MPS float16** (previous code) | **Yes** | `!`, `!`, `!`, `!` (token id 0) |
| MPS float32 | No | `\n`, `[`, ` `, `"` — JSON-like |
| **MPS bfloat16** | No | `\n`, `[`, ` `, `"` — JSON-like |
| CPU float32 | No | same as bf16 |
| MPS float16 + chat template | Yes | `!` repetition |

**Primary cause:** `AntaresEngine` forced `torch.float16` on MPS while `config.json` specifies `"dtype": "bfloat16"`. Float16 on MPS for GraniteMoeHybrid produces NaN/inf logits → degenerate token id 0 (`!`).

**Not primary cause:** Chat template omission on raw prompt — bfloat16 raw prompt generates non-degenerate output. Applying chat template with bf16 yields prose, not JSON (instruct formatting mismatch for the current raw JSON prompt).

**Tokenizer:** Round-trip `SELECT * FROM users WHERE id = ?` — exact match. Files match staged weights.

**Generation config in code:** `max_new_tokens=1024`, `do_sample=False`, no `top_p`, no repetition penalty, no logits processors. (Removed invalid `temperature=0.0` with `do_sample=False`.)

**Staged variant:** 350M GraniteMoeHybrid at `models/350m`; manifest/docs agree on `fdtn-ai/antares-350m`.

### Change made

- `services/antares-server/antares_server/inference.py`: `_resolve_dtype()` uses **bfloat16 on MPS**, float32 on CPU, float16 on CUDA; `pad_token_id` from tokenizer config.

### Observed result after change

- Degenerate `!` output **eliminated** on MPS.
- In-process analyze still returns `completed_no_findings` because model output is **malformed JSON** (truncated array, wrong field shapes e.g. `"cwe": "10"`) — `_parse_findings` regex finds no valid array.
- **All prior Antares results remain invalid for detection quality.** Forward pass is partially restored; structured output contract is not yet met.

### Recommendation (not implemented — not instrumentation)

- Consider Granite chat template + JSON instruction alignment, or a JSON repair pass — separate from dtype fix; do not interpret 0-findings as model accuracy until parse succeeds.

---

## 2. Peak memory measured the wrong process

### Root cause

`scripts/validate-peak-memory.py` (prior version) called `AntaresEngine` / `LlamaCppEvalEngine` **in-process** and used `psutil.Process()` = validation script RSS (~222–478 MiB). Host-native servers on `:8090`/`:8091` were separate processes.

### Change made

Rewrote `scripts/validate-peak-memory.py` to:

- Resolve PIDs via `lsof -iTCP:8090/8091`
- Sample RSS every 100ms during HTTP `POST /v1/analyze` + `POST /v1/unload`
- Report per-server baseline / during / after_unload / second cycle
- Include system memory + swap snapshots

### Observed result (2026-08-24, corrected method)

| Server | Baseline RSS | Peak during inference | After unload | 2nd cycle peak |
|--------|--------------|----------------------|--------------|----------------|
| **Antares :8090** | 301 MiB | **546 MiB** | 546 MiB (no drop) | — |
| **Foundation-Sec :8091** | 53 MiB | **6,551 MiB** | **95 MiB** | **9,302 MiB** |

System during Foundation-Sec peak: ~69% RAM used, **~9.4 GB swap used** — 24 GB Mac under memory pressure.

**Unload behavior:** Foundation-Sec on_demand unload returns RSS to ~95 MiB (GGUF mapping released). Antares on_demand unload did **not** reduce RSS in this run (546 MiB retained — likely MPS allocator cache).

**Anonymous vs file-backed:** macOS `psutil` denied `memory_maps` for sampled PIDs; breakdown is `null` in report. Linux re-run should populate both.

---

## 3. Egress probe bypassed in every run

### Why `SHIFT_LEFT_SKIP_EGRESS_PROBE=1` was set

1. **Model servers on internet-connected Mac:** `assert_egress_blocked_at_startup` probes TCP to `1.1.1.1:443`. On a normal Mac this **succeeds** → startup fails without skip. Skip is documented for local dev only (`docs/distribution-and-sovereignty.md`).

2. **Orchestrator in Docker on `edge` network:** Without skip, orchestrator startup fails with `Egress probe succeeded to 1.1.1.1:443` because the container has WAN route. Colima internal-only network also blocked host port publish — separate compose issue.

This is **not a false positive** on loopback model servers; it correctly detects that the **host/container has internet access**. Skip bypasses that check.

### Runtime sovereignty today

| Check | Enforced? |
|-------|-----------|
| EgressGuard during review (example.com, 1.1.1.1 blocked) | **Yes** — verified in verify-runtime path |
| Startup TCP egress probe on model servers | **Only if skip unset** — skipped in all validation runs |
| Orchestrator `deny_egress` startup check | **Skipped** when `SHIFT_LEFT_SKIP_EGRESS_PROBE=1` |

### Changes made

- `scripts/verify-runtime-real-inference.py`: **fails** if `SHIFT_LEFT_SKIP_EGRESS_PROBE` is set; runs `run_egress_probe()` and requires blocked egress (air-gapped host).
- `services/orchestrator/tests/test_verify_runtime_real.py`: regression test for skip rejection.

### Observed result

On this internet-connected Mac, `verify-runtime --real` now **exits immediately** if skip is set, or if skip unset but probe succeeds (host has WAN). Full real verify-runtime requires an air-gapped host or mocked `verify-runtime` without `--real`.

---

## 4. Handler prompt context asymmetry

### Root cause (evidence)

**Mis-routing (instrumentation bug):**

- `KUBERNETES` handler globs were `**/*.yaml` / `**/*.yml` — matched **all** YAML including `ansible/*.yml` before Ansible handler ran.
- `NGINX` glob `**/nginx/**` did not match `nginx/payments.conf` (no leading path segment).

**Prompt asymmetry (before fix):**

| Handler | Context strength |
|---------|------------------|
| Terraform | Explicit: SG, IAM, CIDR exposure |
| Device/firewall | One line: "any-any ALLOW" |
| Ansible | Generic "privilege escalation" — missed NOPASSWD wildcard pattern |
| Nginx | Fell through to generic `.conf` — no TLS/listener guidance |

Side-by-side prompts after fix captured in diagnostic run (ASA any/any now includes explicit `'permit ip any any'` guidance; Terraform includes RFC1918 scoping note).

### Changes made

- Narrowed Kubernetes globs to `deploy/`, `k8s/`, `kubernetes/`, `*netpol*`
- Added **NGINX** handler; fixed Ansible globs (`ansible/**`)
- Expanded DEVICE, ANSIBLE, TERRAFORM `prompt_context`
- `foundation_sec_server/preprocess.py`: strip `#` comment lines before evaluation

### Fixture rerun (after handler fixes, real inference)

| Case | Before | After (2026-08-24) |
|------|--------|---------------------|
| firewall permissive | not flagged | **not flagged** (still FN) |
| firewall least-privilege | zero findings ✓ | zero findings ✓ |
| terraform permissive | flagged ✓ | flagged ✓ (now CWE-284) |
| terraform scoped (10.0.0.0/8) | zero findings ✓ | **still flagged** (model hedges “typically intended”) |

Prompt/context improvements alone did not eliminate terraform scoped FP in this run. Corpus not rerun per instructions.

---

## 5. False positives — handler bugs

### clean-terraform-scoped (10.0.0.0/8)

- **Cause:** Model flagged "Broad CIDR" without accepting RFC1918 intent.
- **Fix:** Terraform prompt now states RFC1918 `/8` supernets are often intentional; comment lines stripped.
- **Retest:** Post-fix fixture run **still flagged** (low severity, hedged description). Prompt-only fix insufficient — item 6 handler-asserted CWE may be needed for policy, not more prompt tuning now.

### messy-terraform-commented

- **Cause:** Active resource block uses 10.0.0.0/8; leading `#` line was explanatory, not an inactive rule.
- **Fix:** Comment stripping + RFC1918 prompt context.
- **Retest:** Not in 4-fixture subset; corpus re-run deferred.

### Tests added

`services/foundation-sec-server/tests/test_preprocess_handlers.py` — routing + comment stripping.

---

## 6. CWE assertion vs policy_severity (recommendation only — no change)

### Where CWE originates today

| Source | CWE |
|--------|-----|
| Foundation-Sec model JSON | `finding.cwe` → `model_asserted` via `FoundationSecClient._normalize` |
| Scripted engine | Hard-coded `CWE-284` in rules |
| Antares model JSON | `finding.cwe` on code findings |

### policy_severity derivation (`shift_left/policy/severity.py`)

Deterministic precedence: **CWE class map → trace pattern → file suffix → unclassified**. Terraform 0.0.0.0/0 flagged as **CWE-20** maps differently than **CWE-284**.

### Recommendation (before changing)

1. Add `handler_asserted_cwe` from matched handler rule (deterministic) when handler pre-screens a construct.
2. Keep `model_asserted_cwe` as advisory field on Finding.
3. Derive `policy_severity` from **handler_asserted_cwe** when present; fall back to construct type; never from raw model CWE alone.
4. Audit existing policy rules against CWE-284 vs CWE-20 for network exposure rules.

**Not implemented** — requires schema + policy migration.

---

## Summary: (a) instrumentation bugs vs (b) genuine model behavior

### (a) Invalidated measurement / config bugs (fixed or flagged)

- MPS float16 Antares forward pass broken (NaN logits)
- Peak RSS measured wrong process
- Egress startup probe skipped in all validation runs
- Kubernetes glob swallowed Ansible paths
- Nginx path mis-routed to generic handler
- `_analyze_file` treated dict as truthy “flagged” (fixed earlier in validate-real-inference.py)

### (b) Genuine behavior surviving corrected measurement

- Foundation-Sec Q8_0 peaks ~6.5 GB RSS during inference; unload returns to ~95 MiB
- Terraform permissive 0.0.0.0/0 flagged with real model (CWE-20 asserted by model)
- Least-privilege firewall/terraform fixtures: zero findings (stable)
- ASA any/any, nginx-no-tls, ansible-wildcard-sudo: still missed by real model after handler prompt fixes (needs corpus re-run; not tuned)

---

## Next steps (operator)

1. **Air-gapped or probe-blocked host:** rerun `verify-runtime --real` without `SHIFT_LEFT_SKIP_EGRESS_PROBE`.
2. **Antares:** confirm JSON schema compliance after bf16 fix; until then treat Antares leg as **not validated**.
3. **Peak memory:** rerun on Linux for anonymous/file-backed split; monitor swap on 24 GB Mac before production on_demand reviews.
4. **Corpus:** rerun `validate-real-inference.py --corpus-only` only after 1–3 satisfied on target topology.
