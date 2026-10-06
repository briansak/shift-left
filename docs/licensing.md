# Licensing

This document is the operator reference for model-weight licenses, checksums, and Apache-2.0 redistribution. Project source is Apache-2.0 (`LICENSE`); weights are not in git.

Operator-verified inputs (2026-08-23):

- **Antares-350M** and **Foundation-Sec-1.1-8B-Instruct** weights are **Apache 2.0**.
- **Redistribution permitted**, including commercial redistribution and offline bundles.
- **Hugging Face gating** on Antares is an **access mechanism** (agreement + token), **not** a license restriction.
- Bundled distribution is permitted **subject to Apache 2.0 obligations** below.

> **Legal boundary:** This document describes mechanical compliance requirements only.
> Questions requiring legal interpretation → your organization's OSS licensing contact.

---

## Verified model artifacts

| Model | HF repo | Filename | SHA256 | License | HF gate (direct download) | Bundling permitted |
|-------|---------|----------|--------|---------|---------------------------|-------------------|
| Antares-1B | `fdtn-ai/antares-1b` | `model.safetensors` | `6ba4155a50cd0cede3e10285b0d84b460dcc3caa0175a424e14d3bb606fda675` | Apache-2.0 | **Yes** — accept terms + `HF_TOKEN` | **Yes** |
| Antares-350M | `fdtn-ai/antares-350m` | `model.safetensors` | `298dc28c73ba1e02528d5dbc16a064a654c60a5853c131f55934678d85abf121` | Apache-2.0 | **Yes** — accept terms + `HF_TOKEN` | **Yes** (below minimum variant) |
| Foundation-Sec Q8_0 | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF` | `foundation-sec-1.1-8b-instruct-q8_0.gguf` | `ea401b43ee9e79607ae34157e88c3b03c468b50b5f4194e7c82b9e3130e0b2e5` | Apache-2.0 | No (public repo) | **Yes** |
| Foundation-Sec Q4_K_M | `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF` | `foundation-sec-1.1-8b-instruct-q4_k_m.gguf` | `5813d725b38f0da1eac34486e44b70b0f728c2e2881c96873def69e76f8421ed` | Apache-2.0 | No (public repo) | **Yes** |

**Config keys:** `models.antares.hf_repo_id`, `models.foundation_sec.hf_repo_id`, `hf_repo_id_low_memory`, `gguf_glob`, `gguf_glob_low_memory`.

**Prewarm manifest:** copy `config/prewarm-manifest.example.json` → `models/.prewarm-manifest.json`. Startup self-check and model servers verify SHA256 when manifest is present.

---

## Project license vs model licenses

| Artifact | License | In git repo? |
|----------|---------|--------------|
| Shift-Left source code (this repository) | Apache-2.0 (`LICENSE`) | Yes |
| Model weights | Apache-2.0 (per upstream model cards) | **No** — staged under `models/` or bundled separately |
| Python/runtime dependencies | Per `pyproject.toml` / lockfiles | See `THIRD_PARTY_NOTICES.md` |

---

## Apache 2.0 obligations (enforced)

These are **build/bundle requirements**, not documentation-only:

1. **Full license text** — ship `licenses/APACHE-2.0.txt` alongside any redistributed weights (`scripts/check-bundle-compliance.py` enforces this).
2. **Retain upstream attribution** — preserve upstream `LICENSE`, `README.md`, and any `NOTICE` files from each model repo in the bundle unchanged.
3. **Local quantization = modification** — if you quantize or convert weights locally (rather than pulling a published GGUF), emit a modification notice via:
   ```bash
   python scripts/emit-quant-modification-notice.py \
     --source /path/to/upstream.gguf \
     --output /path/to/local-quant.gguf \
     --tool-version $(llama-quantize --version)
   ```
   The notice records source/output SHA256, tool name/version, and change summary (Apache 2.0 §4).
4. **Bundle compliance gate** — `python scripts/check-bundle-compliance.py <bundle-dir>` **must pass** before producing an offline artifact. Missing license text, model `LICENSE`, or `THIRD_PARTY_NOTICES.md` fails the build.

---

## Operational notes

### Direct download (connected install)

| Model | Steps |
|-------|-------|
| Antares-1B | 1) Accept agreement at https://huggingface.co/fdtn-ai/antares-1b 2) Set `HF_TOKEN` in `.env` 3) `./shift-left install-antares` |
| Antares-350M | Below `antares_triage.minimum_variant: 1b` — not staged by `install-antares` |
| Foundation-Sec Q8_0 | `./scripts/download-foundation-sec-model.sh` (optional `HF_TOKEN` if auth required) |
| Foundation-Sec Q4_K_M | Stage from `fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF`; set `use_low_memory: true` |

`shift-left install` invokes staging scripts when weights are missing. **Gated Antares failures produce actionable messages** (accept terms + token), not raw 401 tracebacks.

### Offline bundle recipients

Downstream recipients of an offline bundle must receive:

- All staged weight files with upstream `LICENSE` / `README.md` / `NOTICE` (if any)
- `licenses/APACHE-2.0.txt` (full text)
- `THIRD_PARTY_NOTICES.md`
- Any `*.MODIFICATIONS.json` files for locally quantized artifacts

If they **redistribute further**, they must retain Apache 2.0 attribution and license text per upstream terms.

### Weights not in git

Model weights are **never committed** to this repository. Operators stage under `models/` or produce offline bundles separately.

---

## Reference data (CVE / CWE)

| Source | Runtime use | License |
|--------|-------------|---------|
| NVD API 2.0 | Operator sync only (`sync-reference-data --fetch-nvd`) | Confirm NIST terms with your OSS contact before redistributing fetched CVE JSON |
| MITRE CWE catalog | Bundled dictionary + optional operator fetch | CWE™ © The MITRE Corporation; [Terms of Use](https://cwe.mitre.org/about/termsofuse.html) |
| Bundled `reference-seed/` | Shipped scaffolding | Project Apache-2.0 |

---

## Offline bundle status

Model-weight licensing is Apache-2.0. Bundle production still requires `check-bundle-compliance.py`. Wheel vendoring is separate — [air-gapped-install.md](air-gapped-install.md).

---

## MITRE CWE reference data

The UI CWE reference popover uses `data/cwe/cwe-dictionary.json`, generated offline from a local MITRE CWE catalog XML export (`scripts/build-cwe-dictionary.py`). Runtime lookup reads this bundled file only — no network access.

**Attribution:** CWE™ is a trademark and © 2006–2026 The MITRE Corporation. CWE content is used under the [MITRE CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html). Popover `url` fields are plain text for attribution and are not rendered as live links.

Refresh procedure: see `data/cwe/README.md`.
