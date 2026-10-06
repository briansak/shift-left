# Sovereign Shift-Left — Remediation Report (Items 1–3)

**Date:** 2026-08-24  
**Scope:** Memory configuration, Antares raw-output inspection, schema v5 (`handler_asserted_cwe` + enrichment).  
**Explicitly out of scope:** Phase 4, unseen-corpus re-run, prompt tuning for scores.

Artifacts: `validation/reports/memory-cycles-report.json`, `validation/reports/antares-raw-captures.json`, `validation/reports/handler-cwe-coverage.json`.

---

## Item 1 — Memory (blocking)

### 1a. Cross-cycle growth — root cause

**Prior signal (9.3 GB cycle 2 vs 6.5 GB cycle 1) was a measurement artifact, not KV-cache accumulation.**

Evidence: the old `validate-peak-memory.py` stage `foundation_sec_second_cycle` ran **two** analyze+unload pairs inside one sampled window (`second_cycle=True`). That inflated the “second cycle” peak versus an isolated single cycle.

Corrected four isolated cycles (`scripts/investigate-memory-cycles.py`, one `POST /v1/analyze` + `POST /v1/unload` each):

| Cycle | Peak RSS (MiB) | After unload (MiB) | Swap used (MiB) | Analyze wall (ms) |
|------:|---------------:|-------------------:|----------------:|------------------:|
| 1 | 9164.33 | 92.83 | 10516 | 13362 |
| 2 | 9303.53 | 92.16 | 10619 | 9526 |
| 3 | 9302.53 | 91.97 | 10957 | 9644 |
| 4 | 9303.91 | 126.19 | 10957 | 9417 |

**Conclusion:** Peak **plateaus after cycle 1** (~9.16–9.30 GB); it does **not** keep climbing. After unload, RSS returns to ~92 MiB, confirming GGUF weights and llama.cpp context are released (`del self._llm` + `gc.collect()` added in `engine.py`).

**n_ctx:** Server reported `n_ctx=8192` for all cycles — the second cycle was **not** given a larger context.

**Anonymous vs file-backed:** `memory_maps()` breakdown returned `null` on this macOS/Python 3.14/psutil combo (AccessDenied-style gap). RSS alone shows unload drops from ~9.3 GB → ~92 MiB, consistent with releasing resident anonymous KV + compute buffers while mmap’d GGUF pages drop out of the working set.

### 1b. Q4_K_M comparison

**Blocked:** `models/foundation-sec-q4_k_m/` is not staged (only `models/foundation-sec-q8_0/` present). Identical cycle measurement and fixture quality comparison under Q4_K_M **cannot be run** until `./scripts/download-foundation-sec-model.sh` (or equivalent) stages the Q4 weights.

### 1c. Context budget

| Setting | KV cache estimate (FP16, 32L/8KV) | Chunk usable tokens |
|---------|----------------------------------:|--------------------:|
| `n_ctx=8192` (current server) | ~1024 MiB | 6272 |
| `n_ctx=4096` (recommended default) | ~512 MiB | 2176 |
| `n_ctx=2048` | ~256 MiB | 128 |

Typical validation hunks are tens of lines (≪2000 tokens). **`max_context_tokens: 4096`** in `config/shift-left.example.yaml` comfortably covers realistic diff hunks while halving KV reservation vs 8192. Config key: `models.foundation_sec.max_context_tokens` / env `FOUNDATION_SEC_N_CTX`.

Q8_0 weight file ~8.5 GB + 512 MiB KV + Antares ~350–750 MiB still exceeds comfortable headroom on a 24 GB Mac when swap is already warm.

### 1d. Antares retained memory

`torch.mps.empty_cache()` + `gc.collect()` added on Antares unload (`inference.py`).

**Observed on the long-running `:8090` server** (10 consecutive analyze+unload cycles after other load tests, swap ~11 GB active):

| Cycle | RSS after unload (MiB) |
|------:|-----------------------:|
| 1 | 349 |
| 4 | 598 |
| 10 | 749 |

**Retained memory grows ~25 MiB per review — not flat.** Acceptable only if the server process is recycled; unacceptable for an always-on daemon without a restart strategy.

### 1e. Wall-clock timing

**Under active swap** (this run, ~10.5–11 GB swap used):

| Stage | Antares (code hunk) | Foundation-Sec (config hunk) |
|-------|--------------------:|-----------------------------:|
| Analyze (load+infer+unload, on_demand) | ~3.4–3.6 s | ~9.4–13.4 s (cycle 1 slower) |
| Extra `/v1/unload` | ~4 ms | ~5–27 ms |

End-to-end review estimates (sequential, single hunk each, swap active):

| PR type | Estimated time |
|---------|---------------:|
| Config-only | ~10 s |
| Code-only | ~3.5 s |
| Both | ~13–14 s |

**Without swap:** not measured on this host while ~11 GB swap remained pinned from Q8_0 peaks. Expect Foundation-Sec analyze to drop roughly to the cycle 2–4 band (~9.5 s) vs cycle 1 cold (~13 s); Antares should stay ~2–3 s **if** the server is fresh. A clean non-swapping measurement requires staging Q4_K_M + `n_ctx=4096` and rebooting swap (or a 32 GB+ host).

### Recommended default configuration (24 GB Apple Silicon)

```yaml
models:
  foundation_sec:
    use_low_memory: true          # Q4_K_M (~4.9 GB weights)
    max_context_tokens: 4096      # halve KV vs 8192
    load_strategy: on_demand
  antares:
    load_strategy: on_demand
    # recycle antares-server process periodically — retained MPS memory grows
```

**Justification:** Q8_0 at `n_ctx=8192` peaks ~9.3 GB RSS and drove ~11 GB swap on this 24 GB Mac — unreliable for timing and quality. Q4 + 4096 targets ~5.4 GB model footprint + ~0.35 GB Antares ≈ **6 GB**, which should avoid swap on 24 GB **once Q4 weights are staged and Antares leak is bounded by process recycle**.

If Q4 cannot be staged: **plainly insufficient** for swap-free Q8_0 operation on 24 GB; use **≥32 GB** unified memory or run Foundation-Sec and Antares **never concurrently** with server restarts between stages.

---

## Item 2 — Antares raw output (inspect before parser changes)

**No Antares detection-quality conclusion is supported until it emits contract-valid output.**

Staged variant: **Antares-350M** at `models/350m` — matches config example, prewarm manifest, and model card. Model card describes a **terminal agent** (`grep`/`find`/`cat`, `submit_vulnerable_files`), not diff-hunk JSON.

Inference settings: `max_new_tokens=1024`, `do_sample=False`, **no stop sequences**, **no grammar/JSON mode/logits processor**. Structured JSON mode is feasible via Hugging Face `response_format` or constrained decoding but **not implemented** on this serving path.

Full captures: `validation/reports/antares-raw-captures.json`.

### Fixture: SQLi (`app/db.py`)

**Prompt (verbatim):**

```
You are Antares, a security model that localizes likely vulnerabilities in code changes.
Analyze the diff hunk below and respond with ONLY a JSON array (no markdown fences).
Each object must include:
  file_path, line_start, line_end, cwe, severity (info|low|medium|high|critical),
  confidence (0.0-1.0), title, description, evidence, trace

If no likely issue is present, return [].

File: app/db.py
Lines: 2-3
```diff
 def lookup_user(username):
-    query = "SELECT * FROM users WHERE id = ?"
+    query = f"SELECT * FROM users WHERE username = '{username}'"
     cursor.execute(query)

```
JSON array:
```

**Raw completion (verbatim):**

```

[
  {"file_path": "app/db.py", "line_start": 2, "line_end": 2, "cwe": "10", "severity": "low", "title": "Lookup user function", "description": "Localizes likely SQL injection vulnerability in the lookup_user function", "evidence": "The function constructs a SQL query with an unescaped user input (username) directly in the query string", "confidence": 0.9}, {"file_path": "app/db.py", "line_start": 3, "line_end": 3, "cwe": "10", "severity": "low", "title": "Lookup user function", "description": "Localizes likely SQL injection vulnerability in the lookup_user function", "evidence": "The function constructs a SQL query with an unescaped user input (username) directly in the query string", "confidence": 0.9}
```

**Failure mode:** **(a)/(b)** — array **missing closing `]`**; regex extractor finds no complete `[...]` → **0 parsed findings**. Duplicate objects; `cwe` is `"10"` not `CWE-89`; no `trace` field.

### Fixture: path traversal (`app/files.py`)

**Raw completion begins with** `` ```json `` **fence (violates prompt)**, then **six duplicate objects** (~2808 chars). Parser returns 6 findings but schema contract violated (fence, repetition, `cwe: "misc"`).

**Failure mode:** **(b)/(d)** — format non-compliance and repetition under diff-hunk prompting; agentic/tool loop would enforce submission schema.

### Fixture: hardcoded secret (`config/settings.py`)

**Raw completion:** JavaScript-style object (`single quotes`, unquoted keys, **duplicate `severity` keys**). **Invalid JSON** → 0 parsed findings.

**Failure mode:** **(b)** — malformed from first tokens.

### Agent loop vs diff-hunk (scope only, not implemented)

Official Antares use: multi-turn **terminal tool loop** with CWE-guided repo exploration and structured file submission. Integrating would require: agent runtime (shell sandbox), conversation state, tool parsers, reward/submit schema, and orchestrator routing — **large Phase 4+ scope**, not this pass.

---

## Item 3 — Schema pass (v4 → v5, single migration)

### 3a. `handler_asserted_cwe`

**Root cause:** `policy_severity` was derived from model `cwe` (and path heuristics) — Terraform 0.0.0.0/0 reported as CWE-20 showed model CWE is unreliable for policy.

**Changes (`CURRENT_SCHEMA_VERSION = 5`):**

- `Finding.model_asserted_cwe` — advisory (legacy `cwe` alias preserved).
- `Finding.handler_asserted_cwe` — set by deterministic handler rules (`foundation_sec_server/handlers/cwe_rules.py`), attached in `ConfigAnalyzer` and `ScriptedEvalEngine`.
- `derive_policy_severity()` uses **`handler_asserted_cwe` only** — no model CWE, trace, or suffix fallback.
- Policy rules referencing `model_asserted_cwe` fail validation (like `model_asserted_severity`).
- PR comment formatter labels model vs handler CWE separately.

**Unclassified rate (fixtures + corpus, handler rules only):**

| Metric | Value |
|--------|------:|
| Total entries | 16 |
| Handler-classified | 4 (25%) |
| **Unclassified** | **12 (75%)** |

Classified: firewall any/any, terraform 0.0.0.0/0 patterns. Unclassified: k8s, ansible, nginx, scoped/clean/messy cases — **policy currently has little deterministic CWE signal for most corpus entries.**

Antares code findings have **no handler rules** → `policy_severity=unclassified` unless code handlers are added later.

### 3b. Enrichment / ReviewSummary

Already specified in schema v4; v5 consolidates with handler CWE:

- Per-finding: `model_context`, `recommended_actions`, `enrichment_source`, `enrichment_generated_at`.
- `ReviewSummary` with `is_advisory: true` structurally.
- Policy loader forbids all enrichment/summary fields.
- `enrichment.enabled` default **false** with latency comment in example config.
- `ScriptedEvalEngine` / `ScriptedEnrichmentEngine` emit `[FIXTURE]` prose for tests.
- Enrichment failure path: `enrichment_unavailable` → PR comment “reviewer summary unavailable”; never changes policy.

### 3c. Migration consistency

- Single version bump **4 → 5**; stale config fails loudly.
- Updated: schema, severity engine, policy engine/loader, DB columns (`handler_asserted_cwe`), clients, PR formatter, tests (`test_handler_asserted_cwe.py`, policy/enrichment tests).
- Determinism tests remain scoped to findings + policy decisions; prose excluded.

### Tests

```
21 passed — test_handler_asserted_cwe, test_policy_engine, test_enrichment_schema
```

---

## Code touched (summary)

| Area | Files |
|------|-------|
| Memory | `scripts/investigate-memory-cycles.py`, `foundation_sec_server/engine.py` (`gc.collect` on unload), `antares_server/inference.py` (`mps.empty_cache` + `gc.collect`) |
| Handler CWE | `handlers/cwe_rules.py`, `analyzer.py`, orchestrator severity/clients/schema/DB |
| Antares inspect | `scripts/capture-antares-raw.py` |
| Coverage report | `scripts/report-handler-cwe-coverage.py` |
| Config | `config/shift-left.example.yaml` — schema 5, `max_context_tokens: 4096` |

---

## Next steps (explicitly deferred)

1. Stage Q4_K_M and re-run memory item 1b on a swap-cleared host.
2. Recycle or fix Antares server retained-memory growth before long-running deployments.
3. Antares: agent loop or constrained JSON — **after** contract-valid output path exists.
4. Expand handler CWE rules (k8s/ansible/nginx) to reduce 75% unclassified rate.
5. Unseen corpus + prompt tuning — **separate run**, not this pass.
