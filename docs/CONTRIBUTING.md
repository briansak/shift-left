# Contributing

This document is for people changing Shift-Left source. Operators installing the product should start at the root [README.md](../README.md).

## Layout

| Path | Role |
|------|------|
| `cli/shift_left_cli/` | Operator CLI (`./shift-left`) |
| `services/orchestrator/` | FastAPI orchestrator, parsers, policy, UI |
| `services/foundation-sec-server/` | Config/IaC GGUF inference |
| `services/antares-server/` | Antares agent + Docker sandbox |
| `services/shift-left-shared/` | Shared bind/weight helpers |
| `config/` | Example YAML, Forgejo, runner |
| `docs/` | Public documentation (this tree) |
| `validation/corpus/` | Labeled generated + holdout configs |
| `scripts/` | Install, downloads, `generate_docs.py`, `generate-openapi.py` |

## Tests

Use the repo venv. `python` may not be on `PATH`.

```bash
.venv/bin/pytest services/orchestrator/tests -q
PYTHONPATH=services/foundation-sec-server:services/orchestrator:services/shift-left-shared \
  .venv/bin/pytest services/foundation-sec-server/tests -q
PYTHONPATH=services/antares-server:services/shift-left-shared \
  .venv/bin/pytest services/antares-server/tests -q
```

Platform rule tests live next to fixtures (`test_asa_rules.py`, `test_ftd_rules.py`, `test_ios_xe_rules.py`, `test_nx_os_rules.py`). Adding a rule: [writing-rules.md](writing-rules.md).

### Foundation-Sec collection on an internet-connected host

`services/foundation-sec-server/tests/test_scripted_api.py` and `test_secret_log_guard.py` import `foundation_sec_server.main`. Import runs `startup_model_server`, which dials TCP `1.1.1.1:443`. If that dial connects, collection raises `RuntimeError: foundation-sec-server sovereignty check failed: Egress probe succeeded to 1.1.1.1:443`. That is the sovereignty check working. It is not a corpus or assertion failure, and the rest of the file never runs.

Run the suite where that dial cannot connect. A macOS sandbox that denies network is enough (`TestClient` does not need a socket):

```bash
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  env PYTHONPATH=services/foundation-sec-server:services/orchestrator:services/shift-left-shared \
  .venv/bin/pytest services/foundation-sec-server/tests -q
```

On Linux, `unshare -n` (a new network namespace with no routes) is the same idea. `SHIFT_LEFT_SKIP_EGRESS_PROBE=1` skips the dial, so a green run under that variable does not show the check is in place.

## Parity and corpus regression

| Test | Guarantee |
|------|-----------|
| `test_eval_gate_parity.py` | Eval harness (`validation/eval_handlers.py`) and the PR path (`findings_from_config_handlers`) emit the same registry rule ids on labeled corpus files |
| `test_gate_corpus_regression.py` | Labeled files that declare expected rules do not **PASS** the gate; clean labeled files do not **BLOCK** on those rules; `.cfg` outside ASA parser scope stays unclaimed (CWE-657) |

Together they prevent “eval is green but the PR gate missed it” and “we labeled a violation but the gate allowed merge.”

## Fixture discipline

**Never edit a fixture to make a test pass.**

If a test fails, the parser, registry, or label is wrong — not the config snippet. Changing a violation into a clean file (or the reverse) to quiet CI hides a real miss. Holdout `*.labels.json` may be corrected with a written justification when the original label was mistaken; do not reshape the config around a buggy check.

FTD HCL must stay on CiscoDevNet/fmc 2.0.1 syntax. See [supported-platforms.md](supported-platforms.md).

## Generated docs

Rule tables, the config catalog, and OpenAPI are generated:

```bash
make docs
```

Do not hand-edit `docs/supported-platforms.md` rule tables, `docs/configuration-reference.md`, `docs/openapi.yaml`, or `docs/openapi.json`. After route changes run `make docs-openapi` (`scripts/generate-openapi.py`). `test_openapi_spec.py` fails if the committed spec drifts from the app.
