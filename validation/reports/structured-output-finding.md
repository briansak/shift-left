# Foundation-Sec structured output finding

**Primary finding:** Model eval recall for `platform_specific` advisory JSON is dominated
by **prompt-suffix degenerate completions**, not by quantization or parser defects. Three
suffix variants each trigger a different high-probability local continuation that bypasses
the output-format instruction. The best measured result (**13 / 108** TP on Q8_0) was
obtained only with the **defective** colon suffix; correcting it reduces output to zero.

**No further prompt changes** are planned from this finding. Raw completion remains the
authoritative inference path.

## Run configuration

| Field | Value |
|-------|-------|
| Model | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct` |
| Quants evaluated | **Q8_0** (`foundation-sec-1.1-8b-instruct-q8_0.gguf`), **Q4_K_M** (`foundation-sec-1.1-8b-instruct-q4_k_m.gguf`) |
| Runtime | `llama-cpp-python` **0.3.35** |
| `n_ctx` | **4096** |
| Temperature | **0.1** (`engine.py` `run_advisory_completion`) |
| Inference path | **raw completion** (authoritative) |
| Corpus | 148 labeled files (generated + holdout), `best_fit_v1` semantic matcher |
| Determinism | 3 variance runs per quant at T=0.1 — **identical TP** each run (Q8_0: 13/13/13; Q4_K_M: 3/3/3) |

Sources: `platform-specific-variance.json`, `platform-specific-output-volume.json`,
`platform-specific-colon-fix-comparison.md`, `chat-truncation-diagnostic.json`.

## Three prompt suffixes, three degenerate modes

The eval prompt ends with an output-format cue. The model's next token is drawn from local
continuation statistics of that final token, not from the prose instruction above it.

| Prompt suffix (final tokens) | Degenerate completion mode | Rate (Q8_0) | Rate (Q4_K_M) | TP (both quants after fix) |
|------------------------------|----------------------------|-------------|---------------|----------------------------|
| `JSON array:` (colon) | `://` prefix (`://json`, `://\n{…}`) | **136 / 148 (92%)** | **148 / 148 (100%)** | — (defective baseline) |
| `Findings JSON array:\n[` (bracket) | single `]` token → empty `[]` | **126 / 148 (85%)** | majority 1-token `]` in volume sweep | **0 / 0** |
| Model `chat_template.jinja` (chat turn) | one-token `[]` | **77 / 87** labeled files | (chat path; Q8_0 only) | **5 / 108** (under raw) |

### Defective colon suffix (published baseline)

- Prompt ends with bare `JSON array:` — final token is `:`.
- Model continues with `//`, producing `://json` or `://`-prefixed partial JSON.
- Parser sometimes recovers embedded objects after the garbage prefix → **non-zero findings**.
- This is the suffix present in all **published** `platform_specific` numbers:
  - Q8_0: **13 TP / 6 FP / 95 FN** (85 findings emitted)
  - Q4_K_M: **3 TP / 0 FP / 105 FN** (7 findings emitted)

### Bracket suffix (single fix attempt)

- Prompt ends with `Findings JSON array:\n[` — final character is `[`.
- Model closes the opened bracket immediately: completion `]` → parser prepend → `[]`.
- Remaining longer completions are still `://json` garbage; prepend yields `[://json…` (invalid).
- **Both quants collapse to 0 TP, 0 findings emitted** (148/148 files zero findings).

### Chat template path (rejected)

- Same eval content wrapped in Foundation-Sec chat markers via `chat_template.jinja`.
- Model emits one-token `[]` on **77 / 87** labeled files — immediate empty array, not truncation.
- Q8_0: **5 TP / 0 FP / 103 FN** vs **13 TP** on raw completion with colon suffix.
- See `chat-template-finding.md`.

## Parser exoneration

Diagnostic on bracket-suffix Q8_0 completions (`platform-specific-output-volume.json`,
fresh re-inference sample):

| Check | Result |
|-------|--------|
| Decode failures on `]` → `[]` completions | **0** — all parse as valid empty arrays |
| Double-prepend (`[[`) when model emits `[` | **0 / 148** — guard `not stripped.startswith("[")` holds |
| Longer outputs parseable without prepend but broken by prepend | **0** — garbage was already unparseable |
| Salvageable JSON objects in longer `://`-prefixed output | **0** recovered by harness |

**Conclusion:** The 0 TP collapse after the bracket fix is **model output**, not parser
mangling of valid JSON.

## Mechanism

In each case the model emits the **highest-probability local continuation of the final
prompt token** rather than following the output-format instruction:

| Final prompt token | Model continuation | Interpreted result |
|--------------------|--------------------|--------------------|
| `:` | `//` | `://json` URI-scheme hallucination |
| `[` | `]` | Empty JSON array `[]` |
| Chat assistant turn | `[]` | Empty JSON array (chat collapse) |

The prose instruction ("Return ONLY a JSON array…") is overridden by token-level
autocomplete bias at the suffix boundary.

## Implication for the published table

| Metric | Value | Caveat |
|--------|-------|--------|
| Best measured `platform_specific` TP | **13 / 108** (Q8_0, colon suffix) | Obtained through **defective** prompt |
| After suffix fix | **0 / 108** (both quants) | Correct prompt eliminates all findings |
| Q4 vs Q8 gap | 3 vs 13 TP (colon suffix) | **Not robust** — both collapse to 0 when suffix is fixed |

**All published model numbers carry this caveat.** They measure recovery from a prompt
artifact as much as model capability. Do not compare quants, matchers, or prompt variants
without stating which suffix and inference path were used.

## Fifth methodology artifact

This evaluation has now surfaced **five** methodology choices that each moved results by
more than the model's own signal:

1. **Semantic threshold** — `min_semantic_fit=0.12`, `relative_fit_ratio=0.72` in
   `best_fit_v1` matcher gate which findings count as TP.
2. **CWE-overlap matcher** — CWE agreement necessary but not sufficient; semantic fit and
   line overlap required (`model_eval_matching.py`).
3. **Chat template** — raw completion vs `chat_template.jinja` moves Q8_0 TP 13 → 5.
4. **Token budget** — `n_ctx=4096`, usable chunk budget 2176 tokens; truncation boundary
   affects long configs.
5. **Prompt suffix** — colon vs bracket vs chat turn moves Q8_0 TP 13 → 0 (this finding).

Each artifact should be treated as a confound when reading aggregate recall tables.

## Related artifacts

| Report | Contents |
|--------|----------|
| `platform-specific-colon-fix-comparison.md` | Colon vs bracket A/B table |
| `platform-specific-output-volume.json` | Per-file completion tokens and prefixes |
| `platform-specific-variance.json` | 3-run determinism at T=0.1 |
| `chat-template-finding.md` | Chat path rejection |
| `chat-truncation-diagnostic.json` | 77/87 one-token `[]` on chat path |
