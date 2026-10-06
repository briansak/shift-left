# Real-Model Validation Report

**Status:** Partial — offline / bandwidth-constrained run (2026-08-23)  
**Phase 4:** Not started

This report separates **verified metadata** (complete) from **observed inference results** (deferred until online with staged GGUF and inference deps).

---

## 1. Verified pinned metadata

| Model | HF repo | Filename | SHA256 | Local path | Staged? |
|-------|---------|----------|--------|------------|---------|
| Antares-350M | `fdtn-ai/antares-350m` | `model.safetensors` | `298dc28c73ba1e02528d5dbc16a064a654c60a5853c131f55934678d85abf121` | `models/350m/` | **Yes** |
| Foundation-Sec Q8_0 | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF` | `foundation-sec-1.1-8b-instruct-q8_0.gguf` | `ea401b43ee9e79607ae34157e88c3b03c468b50b5f4194e7c82b9e3130e0b2e5` | `models/foundation-sec-q8_0/` | **No** (README only) |
| Foundation-Sec Q4_K_M | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` | `foundation-sec-1.1-8b-instruct-q4_k_m.gguf` | `5813d725b38f0da1eac34486e44b70b0f728c2e2881c96873def69e76f8421ed` | `models/foundation-sec-q4_k_m/` | **No** |

**Self-check (offline):** Antares presence + SHA256 **PASS**. Foundation-Sec GGUF **FAIL** (file not staged).

**Config / manifest:** `config/shift-left.example.yaml`, `config/prewarm-manifest.example.json`, `models/.prewarm-manifest.json`, `shift_left_shared/weights.py`.

---

## 2. Peak RSS — DEFERRED

**Blocked:** Q8_0 GGUF not on disk; `torch` / `llama-cpp-python` not installed in project `.venv` (no pip install on plane).

**Mocked unit test only (not capacity):** `test_on_demand_memory.py` reports ~88 MiB process RSS with mocked clients — proves on_demand **ordering** only.

**When online, run:**

```bash
# After staging weights and installing inference deps (see §7)
python scripts/validate-peak-memory.py --quant q8_0
python scripts/validate-peak-memory.py --quant q4_k_m   # if Q4_K_M staged
```

Expected output: JSON at `validation/reports/peak-memory-report.json` with per-stage `before_mib`, `peak_mib`, `after_mib`, second-cycle growth, allocator retention estimate.

---

## 3. Fixture results (real inference) — DEFERRED

**Scripted baseline (CI, not real model):** `test_firewall_scripted.py` — 5/5 PASS  
- Permissive any/any firewall → flagged  
- Least-privilege firewall → zero findings  
- Permissive Terraform 0.0.0.0/0 → flagged  
- Scoped Terraform → zero findings  

**Real Foundation-Sec:** Not run. When online:

```bash
python scripts/validate-real-inference.py --quant q8_0
```

Report will include `fixture_results[]` with `match: true/false` per case. **Disagreements with scripted engine are reported as-is** (fixtures are not tuned to match the model).

---

## 4. Unseen corpus — DEFERRED

Corpus: `validation/corpus/` (12 entries: 5 bad, 4 clean, 3 messy) + `manifest.json`.

**When online:** same `validate-real-inference.py` run populates:
- Confusion matrix (`tp`, `tn`, `fp`, `fn`)
- `false_positives[]` and `false_negatives[]` with full model output per item

---

## 5. Determinism & chunking — DEFERRED

**Settings (code, not yet observed on real GGUF):**
- Foundation-Sec llama.cpp: `temperature=0.1`, seed not explicitly set
- Antares Transformers: `do_sample=False`, `temperature=0.0`

**When online:** report section `determinism` (3 runs on `bad/firewall-any-any.rules`) and `chunking` (120-rule synthetic Terraform, `max_context_tokens=2048`).

---

## 6. Finding schema fit — DEFERRED

**When online:** `schema_fit` in validation JSON reports population of `file_path`, `line_range`, `cwe`, `evidence`, `trace`, `model_asserted_severity`, and `policy_severity` (including unclassified path for unknown CWE).

---

## 7. Commands to run when back online

```bash
cd <home>/code/shift-left

# 1. Stage weights
cp config/prewarm-manifest.example.json models/.prewarm-manifest.json
# Antares (gated): accept https://huggingface.co/fdtn-ai/antares-350m + set HF_TOKEN in .env
./scripts/download-antares-model.sh

# Foundation-Sec Q8_0 (~8.5 GB)
./scripts/download-foundation-sec-model.sh

# Optional low-memory quant (~4.7 GB)
mkdir -p models/foundation-sec-q4_k_m
hf download fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF \
  --local-dir models/foundation-sec-q4_k_m \
  --include foundation-sec-1.1-8b-instruct-q4_k_m.gguf

# 2. Install inference deps (once)
pip install -e services/shift-left-shared \
            -e services/antares-server \
            -e services/foundation-sec-server \
            -e services/orchestrator

# 3. Self-check (SHA256)
./scripts/self-check.sh --runtime-only

# 4. Real validation
SHIFT_LEFT_SKIP_EGRESS_PROBE=1 python scripts/validate-real-inference.py --quant q8_0
SHIFT_LEFT_SKIP_EGRESS_PROBE=1 python scripts/validate-peak-memory.py --quant q8_0
SHIFT_LEFT_SKIP_EGRESS_PROBE=1 python scripts/validate-peak-memory.py --quant q4_k_m

# 5. Unit tests (scripted CI path)
SHIFT_LEFT_SKIP_EGRESS_PROBE=1 FOUNDATION_SEC_ENGINE=scripted \
  pytest services/orchestrator/tests services/foundation-sec-server/tests -q
```

---

## 8. Licensing & compliance (offline complete)

- **`docs/licensing.md`:** Authoritative for models — Apache 2.0, redistribution permitted, HF gate documented for Antares direct download only.
- **`THIRD_PARTY_NOTICES.md`:** Project vs model license separation.
- **Bundle gate:** `python scripts/check-bundle-compliance.py`
- **Quant modification notice:** `python scripts/emit-quant-modification-notice.py --help`
- **Pytest (offline):** **60 passed**, 1 warning (includes `test_bundle_compliance.py`).

---

## 9. Blockers summary

| Blocker | Impact |
|---------|--------|
| Q8_0 GGUF not staged | No real Foundation-Sec inference, peak memory, corpus, determinism |
| Q4_K_M not staged | No low-memory peak comparison |
| `torch` not in `.venv` | No real Antares inference from validation scripts |
| `llama-cpp-python` not in `.venv` | No real Foundation-Sec even if GGUF present |

**Antares weights on disk are verified by SHA256** but real code-review inference remains deferred until `torch` is installed.

---

*Update this file after running §7 validation commands and paste observed numbers into sections 2–6.*
