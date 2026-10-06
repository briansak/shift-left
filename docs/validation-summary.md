# What we measured

This page is for someone deciding whether to trust Shift-Left findings. It states what was measured and what that means when you use the tool. It is not a research write-up. Underlying artifacts live under [validation/](../validation/).

## What is being claimed

The **deterministic config gate** (structural parsers plus a fixed rule registry) finds a defined set of configuration defects. On the labeled corpus we keep in this repository, every labeled defect was found and no unlabeled defect was asserted.

**Model output is advisory.** Foundation-Sec and Antares were measured on that role and were not reliable enough to block a merge. They do not feed the gate.

## Config rule results

The handlers were scored against fixtures we wrote for ASA, FMC/FTD Terraform, IOS-XE, NX-OS, and generic Terraform (`validation/corpus/config` and `validation/corpus/holdout`). A finding is a **false positive** here when a rule fires on a file whose labels do not include that rule.

| | |
|---|---|
| Labeled files | 202 (151 generated, 51 holdout) |
| Labeled defects | 150 |
| Defects found | 150 |
| False positives | 0 |

The check that keeps this at zero is `test_gate_corpus_regression.py`. The scored report is [`validation/reports/handler-coverage.json`](../validation/reports/handler-coverage.json) (`handler-corpus-v4`). Recompute with `validation/eval_handlers.py`.

The corpus is **self-authored**: we wrote both the configs and the labels. Zero false positives means the parsers and rules agree with those labels. It does not mean the same rules will stay silent on customer configs we have never seen, or that defects outside the registry will be caught.

Three registry rules are disabled (ASA-003, IOS-009, FTD-007) because they were too noisy for a merge gate. They are not in the 150.

## Why model output does not gate

**Foundation-Sec.** On the labeled config fixtures used for model eval, the best structured-finding run found **13 of 108** known defects. Of 85 findings it emitted, **50** quoted evidence that was not text in the file. The practical consequence: treat any Foundation-Sec annotation as optional commentary. Do not block, waive, or close a change because of it.

**Antares.** On the file-localization task quoted on the Antares-1B model card, thirty runs here landed at the same level as that published score (one seeded defect in one repository). The typical result listed **about four candidate files** for that one real file. The real file was in the list on **14 of 30** runs. Results vary enough between runs that a single investigation is weak evidence either way. The practical consequence: the ranked list is a place for a human to start reading, not a verdict that a CWE is or is not present.

## What that means when you use it

- A **gate block** on a handler rule (for example ASA-001) is a match against a defined check. Within that rule’s coverage, the labeled-corpus result is that the check does not invent findings.
- A **clean gate** means none of the enabled rules matched the changed text. It is not a statement that the change is safe, complete, or free of defects the registry does not encode.
- An **investigation candidate list** is a starting point for a human. Rank, absence from the list, and disagreement between two runs are not conclusions.

## Underlying reports

| Report | What it answers |
|--------|-----------------|
| [`validation/reports/handler-coverage.json`](../validation/reports/handler-coverage.json) | Scored handler result: corpus version, 150/150/0 baseline, per-rule counts, parse coverage |
| [`validation/corpus/config`](../validation/corpus/config) and [`validation/corpus/holdout`](../validation/corpus/holdout) | What files and labels those counts were taken from |
| [`validation/reports/model-experiments-comparison.txt`](../validation/reports/model-experiments-comparison.txt) | How many labeled config defects Foundation-Sec found, and how often its evidence was not in the file |
| [`validation/reports/structured-output-finding.md`](../validation/reports/structured-output-finding.md) | The Foundation-Sec structured-finding runs behind those counts |
| [`validation/reports/antares-localization-paired-n30-statistical-report.json`](../validation/reports/antares-localization-paired-n30-statistical-report.json) | Antares vs the published localization score, typical candidate-list length, and spread across thirty runs |
| [`validation/reports/antares-localization-multidefect-v3.json`](../validation/reports/antares-localization-multidefect-v3.json) | The same agent on real CVE fix commits across multiple repositories |

Platform and rule coverage (what the registry actually checks): [supported-platforms.md](supported-platforms.md). How the gate uses those findings: [gate-enforcement.md](gate-enforcement.md).
