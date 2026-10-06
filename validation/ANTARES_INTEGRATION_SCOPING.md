# Antares Integration Scoping Report

**Date:** 2026-08-24  
**Scope:** Investigate official Antares design, reconcile with Shift-Left schema/constraints, recommend integration path. **Item 4 recommendation is for approval only — not implemented.**  
**Implemented in this pass:** Item 5 contract-validation hardening only.

Related: [`validation/REMEDIATION_REPORT.md`](REMEDIATION_REPORT.md), [`validation/reports/antares-raw-captures.json`](reports/antares-raw-captures.json).

---

## 1. Primary-source findings

Sources read for this report (not assumptions from prior prompts):

| Source | URL / location | What it establishes |
|--------|----------------|---------------------|
| Staged model card | `models/350m/README.md` (from `fdtn-ai/antares-350m`) | Agent loop, tool format, submission contract, eval settings |
| Antares project site | https://cisco-foundation-ai.github.io/antares/ | Family specs (350M/1B/3B), File F1, deployment targets |
| Technical report (PDF) | https://cisco-foundation-ai.github.io/antares/technical-report.pdf | Tool schemas (Appendix A.1), CLI deployment (§6), sandbox rules |
| HF model card (1B) | https://huggingface.co/fdtn-ai/antares-1b | CLI bundled in HF Files; same agent protocol as 350M |
| Cisco cookbook quickstart | https://github.com/cisco-foundation-ai/cookbook/blob/main/1_quickstarts/Quickstart_Antares.md | CLI commands (`plan`, `query`, `sweep`), report formats |
| VLoc Bench repo | https://github.com/cisco-foundation-ai/vulnerability-localization-benchmark | Benchmark harness, `vllm_antares` runner, `/v1/completions` endpoint |
| Measured runtime (this host) | `validation/reports/memory-cycles-report.json` | Single diff-hunk pass ~3.4–3.6 s; retained RSS growth |

**Silent / ambiguous in primary sources:**

- **Antares-3B Hugging Face weights:** The project site and technical report describe 3B (File F1 0.223), but our prewarm manifest and staged weights only verify **350M**. Whether 3B is publicly downloadable on HF was not confirmed in this pass (HF fetch timed out).
- **Standalone CLI source repository:** The CLI is **bundled as a ZIP in the Antares-1B Hugging Face repository Files section**, not published as a separate GitHub repo with importable library API. The cookbook documents subprocess usage; whether it is reusable as a Python library is **not stated** — treat as **subprocess-only** unless we unpack and inspect the ZIP.
- **Line-level localization:** Neither the model card nor the technical report promises **line ranges** or per-hunk CWE objects. Output is **file-level**.

### Intended invocation pattern

From the staged 350M model card (`models/350m/README.md`, “How to Get Started”):

> Antares-350M operates as a terminal agent: it receives a system prompt containing a **CWE identifier and its generic category description**, then iteratively generates reasoning and tool calls whose outputs are appended to the conversation context. The model may issue up to **15 terminal calls** and must then terminate through either **`submit_vulnerable_files`** or **`submit_no_vulnerability_found`**.

Generation format (same source):

```
<think> ... </think>
<tool_call> {"name": "terminal", "arguments": {"command": "..."}} </tool_call>
<tool_response> ... </tool_response>   — sandbox output (provided externally)
```

Chat-template + multi-turn loop; **not** single-shot JSON over a diff hunk.

Official eval settings (model card + technical report): **`temperature=0.3`, `top_p=1.0`**, macro-averaged over **3 runs** — not greedy decoding.

VLoc Bench harness adds for Antares (`vllm_antares` runner): endpoint **`/v1/completions`** (raw text, not chat API), **`frequency_penalty=0.3`**, stop tokens `<|end_of_text|>`, `<|start_of_role|>`, generation prefix triggers reasoning mode.

### Tool interface

Technical report Appendix A.1 (quoted structure):

| Tool | Purpose | Parameters |
|------|---------|------------|
| `terminal` | Read-only shell in repo | `command` (string), optional `max_chars` (default **2000**) |
| `submit_vulnerable_files` | Final answer | `ranked_files`: array of repo-relative paths |
| `submit_no_vulnerability_found` | Clean repo declaration | empty object |

Supported commands (eval prompt in report): **`ls`, `find`, `cat`, `head`, `tail`, `grep`, `rg`, `tree`** — read-only navigation/inspection.

Environment (model card + report):

- Repository mounted at **`/workspace/repo/`** (card example) / sandbox snapshot
- **Docker** with **`network=none`**, command timeout (~10 s recommended), resource limits
- CLI copies eligible files into a **temporary read-only snapshot**; symlinks escaping repo discarded (report §CLI release)

This is a **real shell over a sandboxed filesystem snapshot**, not an abstract “read file” API — but commands are **parsed and restricted to read-only inspection**.

### Official CLI / harness

| Artifact | License | Integration mode |
|----------|---------|------------------|
| Antares CLI ZIP | Bundled with **Antares-1B** on Hugging Face (Apache 2.0 model license) | Subprocess; connects to user-hosted **OpenAI-compatible** inference (`/v1/completions` for Antares) |
| Cookbook quickstart | Apache 2.0 cookbook repo | Documents `antares plan`, `antares query`, `antares sweep` |
| VLoc Bench CLI | Apache 2.0 (benchmark repo) | Python package `vulnerability_localization_benchmark.cli` — evaluation/research harness, not product integration |

CLI outputs (quickstart + report): **`report.json`**, **`report.md`**, **`report.sarif`** — candidate **file paths** and associated **CWE IDs** (input CWE for `query`; sweep selects CWEs locally).

### Expected OUTPUT contract

From model card:

> …submits a list of **files** it believes to contain the reported vulnerability.

From Cisco blog (primary messaging, consistent with report):

> Antares outputs a **ranked list of source files** likely to contain a relevant vulnerability, along with the **terminal exploration trace** that led to that result.

**Not** in primary sources:

- Per-finding JSON with `line_start`, `line_end`, `evidence`, model-chosen CWE per hunk
- Structured CWE objects derived from diff analysis

CWE is an **input** to the agent (“Given a CWE description…”), not a reliable **output** field per localized file.

### Variant sizing

From https://cisco-foundation-ai.github.io/antares/ (family table + File F1):

| Variant | File F1 (GRPO) | Stated target | Context |
|---------|------------------|---------------|---------|
| **350M** | **0.135** | Mobile / IoT / Edge | 32K |
| **1B** | **0.209** (highest recall **0.224**) | Laptop / Workstation | 128K |
| **3B** | **0.223** (nearest frontier) | Any single GPU | 128K |

Model card note: 350M can serve as **speculative draft** for larger variants or **standalone in resource-constrained** deployments.

**Assessment:** 350M is **officially supported** but **undersized for repository-scale localization quality** relative to 1B/3B on the benchmark the card itself cites. It is not described as the recommended variant for full repo sweeps; the cookbook quickstart **focuses on Antares-1B**.

---

## 2. Output-contract reconciliation

### Native Antares output vs our `Finding` schema

| Field | Our `Finding` (code path today) | Native Antares output | Mappable? |
|-------|----------------------------------|------------------------|-----------|
| `file_path` | Single file from diff hunk | **Ranked list** of repo-relative paths | Partial — rank ≠ hunk |
| `line_range` | Required for review UI | **Not produced** | **No** |
| `cwe` / `model_asserted_cwe` | Per finding from model | **CWE supplied as task input**, not per-file output | Input only |
| `handler_asserted_cwe` | Deterministic handler rules | No code-path handlers today | Would need new rules |
| `policy_severity` | From `handler_asserted_cwe` only | N/A at file-rank layer | Unclassified unless new rules |
| `confidence` | 0.0–1.0 per finding | Not in submission schema; F1 from set overlap | No direct field |
| `title`, `description`, `evidence` | Prose per finding | **Exploration trace** + analyst review | Trace ≠ point finding |
| `trace` | Model trace string | Full multi-turn terminal transcript | Different shape |
| Exploration metadata | — | Rank order, turns used, commands | New fields needed |

**Conclusion:** Native output is a **`CodeLocalizationResult`** (ranked files + trace + task CWE), not a **`Finding`** with line precision.

### Is `line_range` obtainable?

**Not from the published Antares contract.** The agent submits **file paths only**. Line numbers could only come from:

1. **Post-hoc heuristics** (grep the diff for patterns) — not Antares output; fragile.
2. **A different model/task** (e.g. Foundation-Sec on config, static rules on code) — out of scope for Antares native output.
3. **Future tool** (not in official tool list) — would **not** be backed by the model card.

**Phase 4 implication:** Review UI for code must **not depend on line-level anchors from Antares**. Use file-level cards, trace excerpts, and optional diff overlay by **separate** deterministic logic.

### Schema / policy / formatter implications

If we adopt native Antares:

- Introduce **`CodeLocalization`** (or extend `Finding` with `localization_rank`, `target_kind=code`, nullable `line_range`) — **breaking/UI change**.
- **`policy_severity`:** Antares file ranks alone provide **no handler CWE** → **`unclassified`** under current v5 rules (same 75% problem on config, but for **all** code policy unless we add **code handler rules** (e.g. map changed paths + diff patterns → CWE-89).
- **PR formatter:** Separate section — “**Ranked localization (Antares)**” vs “**Likely findings (Foundation-Sec)**”; do not present file ranks as line-level findings.
- **Gating:** Policy on code would need **deterministic signals** (handler rules, path patterns, severity from asserted CWE) — **not** raw Antares rank.

### CWE on the code path

Antares is conditioned on a **given CWE description**. In Shift-Left, deterministic policy CWE would come from:

- **Operator/config** mapping (e.g. run `antares query --cwe CWE-89` when SQL-related paths change)
- **Future code handler rules** on diff content (mirror config `handler_asserted_cwe`)
- **Not** from model output fields (model may emit `"10"`, `"misc"`, `"security"` — see captures)

---

## 3. Operational fit (measured where possible)

### Latency

**Measured (this host, diff-hunk JSON path — misaligned but baseline):**

- Single Antares analyze+unload: **~3.4–3.6 s** wall (`memory-cycles-report.json`, swap ~11 GB active)

**Official agent loop (primary sources):**

- Up to **15 `terminal` calls + 1 submission** per task (report §5.2.3)
- Each turn = **one generation** (+ sandbox command execution)
- Full **500-task** sweep: **~15 minutes on one H100** with parallel workers (~**2 s amortized per task** on H100 — report abstract)
- Cookbook quickstart: **10–15 minutes** for one query + small sweep (excluding cold start)

**Rough PR-gate estimate on this Mac (350M, MPS, no parallel workers):**

- If ~3.5 s/generation × **~10 turns average** ≈ **35 s inference** + terminal I/O
- One CWE query ≈ **40–90 s**; sweep of **5 CWEs** ≈ **3–8 min**
- **Per diff hunk** (current architecture) is **wrong unit of work**; per **PR + selected CWE(s)** is correct

**Verdict:** **Fits a few-minute gate** for **one targeted CWE query** on small/medium PRs; **repository-wide sweep** or many CWEs is **background/nightly**, not inline gate.

Compare to current misaligned path: **~3.5 s per hunk** but produces **invalid output** — cheap but useless.

### Memory

**Measured:**

- Antares post-unload RSS **349 → 749 MiB** over 10 cycles (same report) — **linear growth**, not flat
- Foundation-Sec Q8_0 peak **~9.3 GB** + **~11 GB swap** on 24 GB Mac (REMEDIATION_REPORT)

**Agent loop requirement:**

- Model should stay **loaded across turns** (multi-turn transcript). **`on_demand` unload after each turn** would multiply load cost (~3.5 s+ each reload) and fight MPS cache behavior.
- **Compatible approach:** dedicated Antares worker process, model **pinned for duration of one localization task**, then exit/recycle (CLI model).

**Variant memory (not measured here — estimate from parameter count):**

- 350M ~0.35–0.75 GB retained (measured)
- 1B ~**3–4×** → ~1–3 GB
- 3B ~**9×** → likely **2–4+ GB** — still smaller than Foundation-Sec Q8, but **concurrent** Antares + Foundation-Sec remains problematic on 24 GB

### Sovereignty

Requirements from report + CLI release notes:

| Need | Official approach | Shift-Left compatible? |
|------|-------------------|------------------------|
| Repo read access | Read-only snapshot, parsed commands | Yes — PR checkout snapshot |
| Network | **`network=none`** in sandbox | Yes — aligns with `deny_egress` |
| Writes | **Forbidden** | Yes — snapshot is read-only |
| Code execution | **Shell commands only** — read-only allowlist | **No execution of repo code** (tests, builds) if allowlist enforced |
| Inference | User-hosted endpoint | Yes — local `:8090` |

**Containment:** Implement CLI-equivalent sandbox: read-only bind mount of PR tree, command parser enforcing allowlist, output truncation (2000 chars), timeout, no network. **Prompt-injection scanning** on tool output (report mentions quarantine) — required for untrusted repo content.

### Determinism

- Official eval: **`temperature=0.3`** → **not deterministic** across runs (report averages **3 runs**)
- GRPO **reduces variance 42–65%** but does not eliminate it
- Greedy decoding (`do_sample=False`) is **not** the published eval protocol; quality impact **unknown**

**Policy engine impact:** File-rank outputs **must not drive policy** without deterministic derived fields. Same as config path post-v5: **`handler_asserted_cwe` or unclassified**. Antares ranks are **advisory localization**, not reproducible gate inputs.

---

## 4. Options (with recommendation)

| Option | Quality | Latency | Memory | Determinism | Sovereignty | Schema impact | Effort |
|--------|---------|---------|--------|-------------|-------------|---------------|--------|
| **A. Official agent loop / CLI** | **High** (matches training; 1B/3B much better F1) | **40 s–8 min** per PR task on laptop; OK for 1 CWE gate | Pin model per task; recycle process; 1B/3B heavier | **Low** at official T=0.3; advisory only | **Strong** if sandbox matches CLI | **New localization type**; file-level; no `line_range` | **Large** — sandbox, loop, CWE selection, report mapping |
| **B. Fix single-pass JSON** | **Poor / misaligned** — model not trained for this | ~3.5 s/hunk | Fits on_demand | Greedy possible but **not card-backed** | OK | Keeps `Finding` but **false capability claim** | Medium — grammar/JSON mode |
| **C. Larger variant (1B/3B)** | Better File F1 (0.209 / 0.223) | Similar turns, faster on GPU | **1–4+ GB** Antares alone | Same as A | Same as A | Same as A | A + model staging + RAM |
| **D. Deterministic rules primary + Antares enrichment** | Policy from rules; Antares adds rank/trace | Rules fast; Antares optional background | Rules negligible | **Rules deterministic**; Antares advisory | Rules trivial; Antares as A | Split **policy findings** vs **localization hints** | Medium–large |
| **E. CWE-targeted `antares query` on changed paths only** (from cookbook) | Good for **known CWE + relevant diff** | **1 query** per mapped CWE | One agent task | Advisory | Same sandbox | Map CLI JSON → localization records | **Medium** — best incremental step |

### Flags — do not claim without source backing

- **Option B** presents Antares as a **structured per-line finding extractor** — **not supported** by model card (§Out-of-Scope: “not designed… proof-of-concept exploits”; intended output is **file list**).
- **Diff-hunk JSON prompting** implies line-level CWE findings — **not in primary sources**.

### Recommendation (for your approval — not implemented)

**Primary: Option A + E hybrid — integrate the official agent protocol (via CLI subprocess or embedded loop matching Appendix A.1), driven by CWE-scoped queries on the PR checkout, not per-hunk JSON.**

**Secondary: Option D — expand deterministic code handler rules** (as on config) for **`handler_asserted_cwe` / policy**, using Antares output only for **advisory ranked files + trace**.

**Reasoning:**

1. Primary sources consistently describe **terminal agent + ranked files**; our failures are **misuse**, not tuning.
2. Antares is a **core product capability** — aligning with the card preserves credibility.
3. PR gate budget allows **one targeted `query --cwe …`**; sweeps remain optional/background.
4. Policy stays deterministic via **handler rules + task CWE**, not model prose.
5. Item 5 proves the current JSON path **must fail closed** until replaced.

**Confidence:** **Medium-high** on architecture (sources are explicit); **medium** on effort/timeline (sandbox + CLI integration); **high** that Option B should be rejected.

**Do not implement until approved.**

If approved, staged weights should move toward **Antares-1B** for localization quality; keep 350M only for resource-constrained edge mode.

---

## 5. Correctness fixes implemented (this pass)

**Problem:** Path-traversal capture previously parsed **6 duplicate, contract-invalid** objects into findings — corrupting downstream policy inputs.

**Changes:**

| File | Change |
|------|--------|
| `services/antares-server/antares_server/contract.py` | Strict schema validation, fence detection, duplicate rejection, CWE catalog check |
| `services/antares-server/antares_server/cwe_catalog.py` | Load CWE IDs from `REFERENCE_DATA_CACHE_DIR` / `reference-seed/cwe` |
| `services/antares-server/antares_server/inference.py` | Contract failure → `outcome: failed`, `failure_class: parse_error`, **empty findings** |
| `services/antares-server/tests/test_contract_validation.py` | Tests against `validation/reports/antares-raw-captures.json` |

**Behavior:**

- Markdown fences → logged + **contract violation** → **FAILED**
- Invalid JSON, missing fields, bad CWE (`"10"`, `"misc"`), duplicates → **FAILED**
- Valid `[]` → `completed_no_findings`
- **Never** `completed_no_findings` when model returned malformed data
- **Never** partially accept findings

**Tests:** `8 passed` in `services/antares-server/tests/test_contract_validation.py`

---

## Explicit status

- **Phase 4:** Not started  
- **Corpus:** Not re-run  
- **Item 4 integration:** **Awaiting approval** — only Item 5 shipped  
- **Detection quality:** Still **not supported** until Antares runs via its **native agent contract**
