# Writing a config rule

This is the contributor checklist for adding a deterministic rule to an existing platform (ASA, FMC/FTD, IOS-XE, NX-OS, or generic Terraform). Operators do not need it. Platform behavior: [supported-platforms.md](supported-platforms.md).

Do not add a new target type here — that is a parser, routing, and corpus project of its own.

## 1. Registry entry

Add a `Rule` to `ALL_RULES` in `services/orchestrator/shift_left/handlers/config/rules/registry.py`:

- `id` — stable (`ASA-0xx`, `FTD-0xx`, `IOS-0xx`, `NXOS-0xx`, `TF-0xx`, `HCL-0xx`)
- `target_type` — one of the five managed types
- `cwe` — must already exist in the CWE dictionary (`assert_cwe_in_catalog`)
- `severity` — `block` or `flag` (this is the gate floor; see [gate-enforcement.md](gate-enforcement.md))
- `parser` — package name used by registry matching
- `description` / `remediation`
- `registry_status` — `enabled` unless the rule is optional (`disabled`) or a pre-match interpretability check (`enforced_prematch`, like HCL-001)
- `waivable` — usually true; CWE-657 unclaimed files are not waivable at the gate config layer

Also add the id to `RULE_HANDLER_NAMES`.

Registry severity drives gate action. Operator YAML may escalate via `policy.operator_escalations` (`rule_id` + `action: block`) but cannot silently downgrade a `block` rule.

## 2. Parser check

Implement a `check_*` in the platform's `checks.py` (or HCL equivalent) that returns `ConfigRuleMatch` with `pattern_id=rule.id`, `cwe`, line range, and `construct_key`. Wire it in the platform's check map and in `registry_matching.py` so eval, gate, and parity share one path.

Resolution of objects/groups must run before the check. Unresolved refs belong on the platform's CWE-754 rule (ASA-007, IOS-001, NXOS-001, FTD-008, HCL-001), not as a silent miss.

## 3. Fixtures

For every **enabled** or **enforced_prematch** rule:

| Kind | Where | Count |
|------|--------|-------|
| Generated positive (violation) | `services/orchestrator/tests/fixtures/<platform>/` and `validation/corpus/config/<target_type>/` | at least **2** |
| Generated negative (clean) | same | at least **2** |
| Holdout | `validation/corpus/holdout/<target_type>/` plus `*.labels.json` | at least **1** |

Never edit a fixture to make a test pass. If the parser is wrong, fix the parser. If a label is wrong, fix the label with a justification in `*.labels.json`, not by weakening the config until the assertion goes green.

FTD fixtures must use CiscoDevNet/fmc **2.0.1** syntax (literal `access_control_policy_id`, assignment-form literals). Do not reintroduce `fmc_access_policy`.

## 4. CWE dictionary and severity

- CWE id must be in `data/cwe/cwe-dictionary.json` (rebuild via `scripts/build-cwe-dictionary.py` from a local MITRE XML export if you need a new id)
- `policy.cwe_severity_mapping` / default HIGH for CWE-284/657/754 already cover typical block rules
- Handler asserted CWE on the match is what policy sees — not model output

## 5. Tests that must pass

```bash
.venv/bin/pytest services/orchestrator/tests/test_<platform>_rules.py \
  services/orchestrator/tests/test_eval_gate_parity.py \
  services/orchestrator/tests/test_gate_corpus_regression.py -q
```

- Platform fixture tests: each generated violation matches, each clean file does not
- `test_eval_gate_parity.py` — eval harness and PR-path `findings_from_config_handlers` emit the same registry rule ids
- `test_gate_corpus_regression.py` — labeled corpus files with expected rules do not PASS; clean labeled files do not BLOCK on those rules

Then regenerate public rule tables:

```bash
make docs-platforms
```

## Disabled rules

Keep them in the registry with `registry_status="disabled"` and a reason (see ASA-003, IOS-009, FTD-007). They still appear in [supported-platforms.md](supported-platforms.md) so operators can see what is off.
