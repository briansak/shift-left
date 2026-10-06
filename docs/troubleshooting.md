# Troubleshooting

This is a list of failures we have actually hit, for operators running the stack. Each entry is symptom, cause, and fix. Architecture: [architecture.md](architecture.md). Config keys: [configuration-reference.md](configuration-reference.md).

## CLI-001: platform could not be determined

**Symptom.** A new config review shows one blocking finding, trace `handler:CLI-001`, CWE-754. The title is “Platform could not be determined.” ASA, IOS-XE, and NX-OS rule ids are absent. This is the finding an undeclared config is most likely to hit: any file without platform markers, and without a managed target, produces it.

**Cause.** The file is on the undeclared path. The sniffer found no IOS-XE, NX-OS, or ASA markers, so the gate does not guess a platform and does not run every CLI family. CLI-001 is not waivable. The remedy is a config edit.

**Fix.** Add a managed target in `config/shift-left.yaml`:

```yaml
managed_targets:
  targets:
    - id: edge-fw-01
      display_name: edge-fw-01
      target_type: cisco_ios_xe
      repo: owner/repo
      branch: main
      config_paths:
        - "configs/**/*.cfg"
```

Set `target_type` to `cisco_secure_firewall`, `cisco_ios_xe`, or `cisco_nx_os`, and set `config_paths` so they cover the file. Re-run the review. Do not grant a waiver for CLI-001.

## Schema version mismatch

**Symptom**

```
config/shift-left.yaml: unsupported schema_version 10 (expected 11).
```

or

```
config/shift-left.yaml: missing required schema_version (expected 11).
```

**Cause.** Operator YAML lagged `CURRENT_SCHEMA_VERSION` in `services/orchestrator/shift_left/config.py` (currently 11).

**Fix.** Copy keys from `config/shift-left.example.yaml` and set `schema_version: 11`. Stale keys such as `models.foundation_sec.quant` also refuse to load:

```
stale configuration keys: models.foundation_sec.quant. Use schema_version 11 fields …
```

## Config path resolving outside a mount

**Symptom.** Orchestrator cannot write findings or Antares cannot see checkouts. System page shows a legacy path rewrite. SQLite errors under `/shift-left/data/...`.

**Cause.** YAML used a container-absolute path (`/shift-left/data/repos` or `/data/repos`). The repo bind-mount `.:/shift-left:ro` is read-only. Writable data lives on `SHIFT_LEFT_DATA_DIR=/data` (`./data/findings`, `./data/repos`).

**Fix.** Store repo-relative `data/repos`, `data/findings/shift-left.db`, `data/reference`. Load remaps `/shift-left/data/...` onto the data volume; confirm `legacy_path_rewrites` on `/ui/system`. Do not point sqlite at the read-only tree.

## Antares disabled by default

**Symptom.** Investigation launch returns an error that Antares is not installed, or `/ui/investigations` says to install first. `./shift-left status` shows Antares not staged.

**Cause.** `./shift-left install` stages Foundation-Sec only. Log line:

```
Antares is optional (advisory triage only). Install with: ./shift-left install-antares
```

**Fix.**

```bash
./shift-left install-antares
./shift-left model start antares-server
```

Requires accepted Hugging Face terms and `HF_TOKEN`. Minimum variant is 1B.

## Gated model download failing under TLS interception

**Symptom.** `hf download` / `huggingface_hub` hangs or fails. `httpx` does not honor `SSL_CERT_FILE` on some intercepting proxies. Script output:

```
Antares download requires HF_TOKEN (gated model).
```

or

```
download-antares-model.sh failed — Hugging Face authentication or gated access.
  Accept the model agreement and set HF_TOKEN, then re-run the script.
```

**Cause.** Antares is gated. Corporate TLS inspection breaks the HF CLI. 401/403 if terms are not accepted.

**Fix.** Accept https://huggingface.co/fdtn-ai/antares-1b, set `HF_TOKEN` in `.env` (never commit it). If `hf` cannot complete, download with `curl -fL -C - -H "Authorization: Bearer $HF_TOKEN"` into `models/1b/` (weights, tokenizer, `chat_template.jinja`). SHA256: [licensing.md](licensing.md).

## Model server pointed at the wrong variant

**Symptom.** Antares emits NaN / `!` tokens (350M on MPS float16). Foundation-Sec loads a reasoning GGUF with instruct prompts or the reverse. Health shows an unexpected `gguf` filename.

**Cause.** `models.foundation_sec.model_variant` is `instruct` or `reasoning` with **separate** paths (`local_path` vs `local_path_reasoning`). They are not interchangeable. Antares-350M is below triage minimum.

**Fix.** Point `models.antares.local_path` at `models/1b`. For Foundation-Sec Q4_K_M set `use_low_memory: true` and `local_path_low_memory: models/foundation-sec-q4_k_m`. Restart the model server after path/quant changes. Instruct vs reasoning GGUF globs must match `model_variant`.

## Stale Actions token

**Symptom.** Forgejo workflow cannot call `/api/v1/review` (401). After `./shift-left reset`, new PRs never show reviews.

**Cause.** Repo secret `SHIFT_LEFT_TOKEN` still holds a revoked or pre-reset token. Actions auth is minted at `up` / `new-repo`.

**Fix.** Re-run `./shift-left up` (it resyncs the secret) or:

```bash
./shift-left token mint --label forgejo-actions-ci --actor ci --capabilities review
```

Set Forgejo repo secret `SHIFT_LEFT_TOKEN` to the new `slt_…` value. Confirm `/ui/system` sees a registered runner (`data/forgejo-runner/.runner`).

## Analysis incomplete / handler error on the PR page

**Symptom.** Gate `allowed: false` with `analysis_incomplete`. PR page shows Failure class `handler_error` / stage `handler_match` (or `inference_error` / `generation`).

**Cause.** Fail-closed review: a parser/handler exception or model failure does not become PASS.

**Fix.** Read the message on `/ui/pr/...`. Handler match errors are bugs in platform checks (fix the parser). Inference errors are Foundation-Sec process/weights. Re-run review after the fix; do not waive CWE-657.

## HCL-001 on every Terraform file

**Symptom.** Trace `handler:HCL-001`, CWE-754, even on valid `.tf`.

**Cause.** `python-hcl2` missing in the orchestrator image/venv.

**Fix.** It is declared in `services/orchestrator/pyproject.toml`. Rebuild the orchestrator image. Air-gap: [air-gapped-install.md](air-gapped-install.md).
