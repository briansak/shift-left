#!/usr/bin/env python3
"""Evaluate declarative config handler rules against labeled config corpora."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ORCH):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from shift_left.handlers.config.coverage_report import (  # noqa: E402
    format_parse_coverage_summary,
    parse_coverage_line_parts,
)
from shift_left.handlers.config.parsers.asa.parser import acl_parse_coverage, count_acl_remark_lines  # noqa: E402
from shift_left.handlers.config.parsers.ios_xe.parser import cli_parse_coverage  # noqa: E402
from shift_left.handlers.config.parsers.nx_os.parser import cli_parse_coverage as nx_cli_parse_coverage  # noqa: E402
from shift_left.handlers.config.hcl_parse import compute_hcl_coverage  # noqa: E402
from shift_left.handlers.config.parsers.ftd.parser import (
    FMC_PROVIDER_VERSION,
    FMC_PROVIDER_SCHEMA_PATH,
    audit_ftd_resolver_schema,
    audit_ftd_rule_schema,
)  # noqa: E402
from shift_left.handlers.config.gate_findings import findings_for_corpus_file  # noqa: E402
from shift_left.handlers.config.registry_matching import matched_registry_rule_ids_for_path  # noqa: E402
from shift_left.handlers.config.rules.registry import ALL_RULES, evaluated_rule_ids  # noqa: E402
from shift_left.ui.cwe_dictionary import unrecognized_model_cwe_tally  # noqa: E402
from shift_left.models.schema import PolicyAction  # noqa: E402
from shift_left.policy.engine import PolicyEngine  # noqa: E402

GENERATED_CORPUS_DIR = ROOT / "validation" / "corpus" / "config"
HOLDOUT_CORPUS_DIR = ROOT / "validation" / "corpus" / "holdout"
REPORT_PATH = ROOT / "validation" / "reports" / "handler-coverage.json"

# Versioned handler corpus baseline. Bump when labeled fixtures or registry rules change.
CORPUS_VERSION = "handler-corpus-v4"
CORPUS_VERSION_NOTES = (
    "150 labeled defect instances after CLI-001 undeclared-platform fixtures "
    "(2 generated positives, 1 holdout positive; not waivable). "
    "Supersedes handler-corpus-v3 (147 instances)."
)
PRIOR_CORPUS_VERSION = "handler-corpus-v3"
PRIOR_LABELED_DEFECT_INSTANCE_COUNT = 147

CONFIG_SUFFIXES = {".rules", ".tf", ".hcl", ".conf", ".cfg", ".txt"}

_DISABLED_RULE_REASONS: dict[str, str] = {
    "ASA-003": (
        "enabled=False in registry (permit-without-log is too noisy for production gating)."
    ),
    "FTD-007": (
        "Legitimate internal and lab ALLOW rules often omit intrusion policy "
        "during staged rollouts; rule remains in registry for optional enablement."
    ),
    "IOS-009": (
        "Access-port BPDU guard and port-security requirements vary by campus baseline; "
        "rule remains disabled to avoid false positives on lab and legacy access layers."
    ),
}


def build_rule_gaps() -> list[dict[str, str]]:
    """Registry rules excluded from evaluation — must remain visible in coverage reports."""
    gaps: list[dict[str, str]] = []
    for rule in ALL_RULES:
        if rule.registry_status != "disabled" or not rule.counts_as_coverage_gap:
            continue
        gaps.append(
            {
                "rule_id": rule.id,
                "target_type": rule.target_type,
                "cwe": rule.cwe,
                "severity": rule.severity,
                "status": rule.registry_status,
                "reason": _DISABLED_RULE_REASONS.get(rule.id, rule.description),
            }
        )
    return gaps


@dataclass(frozen=True)
class CorpusEntry:
    rel_path: str
    target_type: str
    virtual_path: str
    expected_rule_ids: frozenset[str]
    expected_gate_cwes: frozenset[str]
    description: str


@dataclass(frozen=True)
class FileEvaluation:
    rel_path: str
    target_type: str
    expected_rule_ids: list[str]
    matched_rule_ids: list[str]
    unexpected_matches: list[str]
    missed_expected: list[str]


def _labels_path(config_path: Path) -> Path:
    return config_path.with_suffix(config_path.suffix + ".labels.json")


def load_corpus(corpus_dir: Path) -> list[CorpusEntry]:
    entries: list[CorpusEntry] = []
    for config_path in sorted(corpus_dir.rglob("*")):
        if not config_path.is_file():
            continue
        if config_path.suffix not in CONFIG_SUFFIXES:
            continue
        labels_file = _labels_path(config_path)
        if not labels_file.is_file():
            raise FileNotFoundError(f"missing labels sidecar for {config_path.relative_to(ROOT)}")
        labels = json.loads(labels_file.read_text())
        rel = str(config_path.relative_to(corpus_dir))
        entries.append(
            CorpusEntry(
                rel_path=rel,
                target_type=str(labels["target_type"]),
                virtual_path=str(labels.get("virtual_path", rel)),
                expected_rule_ids=frozenset(labels.get("expected_rule_ids", [])),
                expected_gate_cwes=frozenset(labels.get("expected_gate_cwes", [])),
                description=str(labels.get("description", "")),
            )
        )
    return entries


def matched_registry_rules(target_type: str, content: str, path: str) -> set[str]:
    return matched_registry_rule_ids_for_path(target_type, path, content)


def enabled_rule_ids() -> list[str]:
    return evaluated_rule_ids()


def compute_parse_coverage(
    generated_entries: list[CorpusEntry],
    holdout_entries: list[CorpusEntry],
) -> dict[str, dict[str, int | float]]:
    """ACL parse coverage per target_type across both corpora."""
    totals: dict[str, dict[str, int]] = {}

    def _accumulate(entries: list[CorpusEntry], corpus_dir: Path) -> None:
        for entry in entries:
            content = (corpus_dir / entry.rel_path).read_text()
            if entry.target_type == "cisco_secure_firewall":
                parsed, total = acl_parse_coverage(content)
                remarks = count_acl_remark_lines(content)
                bucket = totals.setdefault(
                    entry.target_type,
                    {
                        "parsed_acl_lines": 0,
                        "total_acl_bearing_lines": 0,
                        "remark_acl_lines": 0,
                    },
                )
                bucket["parsed_acl_lines"] += parsed
                bucket["total_acl_bearing_lines"] += total
                bucket["remark_acl_lines"] += remarks
                continue
            if entry.target_type in {"cisco_ios_xe", "cisco_nx_os"}:
                coverage_fn = (
                    cli_parse_coverage
                    if entry.target_type == "cisco_ios_xe"
                    else nx_cli_parse_coverage
                )
                parsed, total = coverage_fn(content)
                bucket = totals.setdefault(
                    entry.target_type,
                    {"parsed_cli_lines": 0, "total_evaluable_cli_lines": 0},
                )
                bucket["parsed_cli_lines"] += parsed
                bucket["total_evaluable_cli_lines"] += total
                continue
            if entry.target_type in {"cisco_ftd", "generic_terraform"}:
                coverage = compute_hcl_coverage([content], target_type=entry.target_type)
                bucket = totals.setdefault(
                    entry.target_type,
                    {
                        "parsed_resources": 0,
                        "total_resource_blocks": 0,
                        "parse_failure_files": 0,
                    },
                )
                bucket["parsed_resources"] += coverage.parsed_resources
                bucket["total_resource_blocks"] += coverage.total_resource_blocks
                if coverage.parse_failure_files:
                    bucket["parse_failure_files"] += 1

    _accumulate(generated_entries, GENERATED_CORPUS_DIR)
    _accumulate(holdout_entries, HOLDOUT_CORPUS_DIR)

    report: dict[str, dict[str, int | float]] = {}
    for target_type, counts in sorted(totals.items()):
        if target_type in {"cisco_ios_xe", "cisco_nx_os"}:
            parsed = counts["parsed_cli_lines"]
            total = counts["total_evaluable_cli_lines"]
            ratio = round(parsed / total, 4) if total else 1.0
            report[target_type] = {
                "parsed_cli_lines": parsed,
                "total_evaluable_cli_lines": total,
                "parse_coverage_ratio": ratio,
            }
            continue
        if target_type in {"cisco_ftd", "generic_terraform"}:
            parsed = counts["parsed_resources"]
            total = counts["total_resource_blocks"]
            ratio = round(parsed / total, 4) if total else 1.0
            report[target_type] = {
                "parsed_resources": parsed,
                "total_resource_blocks": total,
                "parse_failure_files": counts.get("parse_failure_files", 0),
                "parse_coverage_ratio": ratio,
            }
            continue
        parsed = counts["parsed_acl_lines"]
        total = counts["total_acl_bearing_lines"]
        ratio = round(parsed / total, 4) if total else 1.0
        report[target_type] = {
            "parsed_acl_lines": parsed,
            "total_acl_bearing_lines": total,
            "remark_acl_lines": counts.get("remark_acl_lines", 0),
            "parse_coverage_ratio": ratio,
        }
    return report


def evaluate_corpus(
    entries: list[CorpusEntry],
    corpus_dir: Path,
) -> tuple[list[FileEvaluation], dict[str, dict]]:
    file_results: list[FileEvaluation] = []
    enabled_ids = enabled_rule_ids()
    stats = {
        rule_id: {
            "true_positives": 0,
            "false_positives": 0,
            "false_negatives": 0,
            "false_positive_files": [],
        }
        for rule_id in enabled_ids
    }

    for entry in entries:
        content = (corpus_dir / entry.rel_path).read_text()
        matched = matched_registry_rules(entry.target_type, content, entry.virtual_path)
        expected = set(entry.expected_rule_ids)
        unexpected = sorted(matched - expected)
        missed = sorted(expected - matched)
        file_results.append(
            FileEvaluation(
                rel_path=entry.rel_path,
                target_type=entry.target_type,
                expected_rule_ids=sorted(expected),
                matched_rule_ids=sorted(matched),
                unexpected_matches=unexpected,
                missed_expected=missed,
            )
        )
        for rule_id in enabled_ids:
            if rule_id in expected and rule_id in matched:
                stats[rule_id]["true_positives"] += 1
            elif rule_id not in expected and rule_id in matched:
                stats[rule_id]["false_positives"] += 1
                stats[rule_id]["false_positive_files"].append(entry.rel_path)
            elif rule_id in expected and rule_id not in matched:
                stats[rule_id]["false_negatives"] += 1

    per_rule: dict[str, dict] = {}
    for rule_id, counts in stats.items():
        tp = counts["true_positives"]
        fp = counts["false_positives"]
        fn = counts["false_negatives"]
        precision = round(tp / (tp + fp), 4) if (tp + fp) else None
        recall = round(tp / (tp + fn), 4) if (tp + fn) else None
        per_rule[rule_id] = {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": precision,
            "recall": recall,
            "false_positive_files": counts["false_positive_files"],
        }

    return file_results, per_rule


def build_handler_baseline(
    *,
    generated_entries: list[CorpusEntry],
    holdout_entries: list[CorpusEntry],
    gen_file_results: list[FileEvaluation],
    hold_file_results: list[FileEvaluation],
    gen_per_rule: dict[str, dict],
    hold_per_rule: dict[str, dict],
) -> dict:
    """Aggregate handler TP/FP/FN across generated + holdout corpora."""
    combined_per_rule: dict[str, dict[str, int]] = {}
    for per_rule in (gen_per_rule, hold_per_rule):
        for rule_id, metrics in per_rule.items():
            bucket = combined_per_rule.setdefault(
                rule_id,
                {"true_positives": 0, "false_positives": 0, "false_negatives": 0},
            )
            bucket["true_positives"] += metrics["true_positives"]
            bucket["false_positives"] += metrics["false_positives"]
            bucket["false_negatives"] += metrics["false_negatives"]

    total_tp = sum(item["true_positives"] for item in combined_per_rule.values())
    total_fp = sum(item["false_positives"] for item in combined_per_rule.values())
    total_fn = sum(item["false_negatives"] for item in combined_per_rule.values())
    labeled_instances = sum(
        len(entry.expected_rule_ids)
        for entry in (*generated_entries, *holdout_entries)
    )
    labeled_files = sum(
        1 for entry in (*generated_entries, *holdout_entries) if entry.expected_rule_ids
    )
    all_files = len(generated_entries) + len(holdout_entries)

    per_target_type: dict[str, dict[str, int]] = {}
    for entry, file_eval in (
        *((entry, result) for entry, result in zip(generated_entries, gen_file_results)),
        *((entry, result) for entry, result in zip(holdout_entries, hold_file_results)),
    ):
        bucket = per_target_type.setdefault(
            entry.target_type,
            {
                "files_total": 0,
                "labeled_files": 0,
                "labeled_defect_instances": 0,
                "true_positives": 0,
                "false_positives": 0,
                "false_negatives": 0,
            },
        )
        bucket["files_total"] += 1
        if entry.expected_rule_ids:
            bucket["labeled_files"] += 1
        bucket["labeled_defect_instances"] += len(entry.expected_rule_ids)
        matched = set(file_eval.matched_rule_ids)
        expected = set(entry.expected_rule_ids)
        bucket["true_positives"] += len(expected & matched)
        bucket["false_positives"] += len(matched - expected)
        bucket["false_negatives"] += len(expected - matched)

    recall = round(total_tp / labeled_instances, 4) if labeled_instances else None
    precision = round(total_tp / (total_tp + total_fp), 4) if (total_tp + total_fp) else None

    return {
        "corpus_version": CORPUS_VERSION,
        "corpus_version_notes": CORPUS_VERSION_NOTES,
        "prior_corpus_version": PRIOR_CORPUS_VERSION,
        "prior_labeled_defect_instance_count": PRIOR_LABELED_DEFECT_INSTANCE_COUNT,
        "files_total": all_files,
        "labeled_files": labeled_files,
        "labeled_defect_instances": labeled_instances,
        "true_positives": total_tp,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "precision": precision,
        "recall": recall,
        "per_target_type": per_target_type,
        "per_rule": combined_per_rule,
    }


def build_corpus_report(
    *,
    corpus_name: str,
    corpus_dir: Path,
    entries: list[CorpusEntry],
    file_results: list[FileEvaluation],
    per_rule: dict,
) -> dict:
    clean_files = sum(1 for item in entries if not item.expected_rule_ids)
    violation_files = len(entries) - clean_files
    perfect_precision = [
        rule_id
        for rule_id, metrics in per_rule.items()
        if metrics["precision"] == 1.0 or metrics["precision"] is None
    ]
    return {
        "corpus_name": corpus_name,
        "corpus_dir": str(corpus_dir.relative_to(ROOT)),
        "summary": {
            "files_total": len(entries),
            "clean_files": clean_files,
            "violation_files": violation_files,
            "enabled_rules_evaluated": len(per_rule),
            "rules_at_full_precision": len(perfect_precision),
            "files_with_unexpected_matches": sum(1 for item in file_results if item.unexpected_matches),
            "files_with_missed_expected": sum(1 for item in file_results if item.missed_expected),
        },
        "per_rule": per_rule,
        "per_file": [
            {
                "path": item.rel_path,
                "target_type": item.target_type,
                "expected_rule_ids": item.expected_rule_ids,
                "matched_rule_ids": item.matched_rule_ids,
                "unexpected_matches": item.unexpected_matches,
                "missed_expected": item.missed_expected,
            }
            for item in file_results
        ],
    }


def _default_eval_config() -> AppConfig:
    from shift_left.config import AppConfig

    return AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": "/tmp/shift-left-eval-gate.db"},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        }
    )


def evaluate_gate_outcomes(
    entries: list[CorpusEntry],
    corpus_dir: Path,
) -> list[dict[str, object]]:
    config = _default_eval_config()
    engine = PolicyEngine(config.policy)
    outcomes: list[dict[str, object]] = []

    for entry in entries:
        content = (corpus_dir / entry.rel_path).read_text()
        path = entry.virtual_path
        findings = findings_for_corpus_file(
            path=path,
            target_type=entry.target_type,
            content=content,
            config=config,
        )
        result = engine.evaluate(
            repo="eval/corpus",
            pr_ref="eval",
            commit_sha="eval",
            findings=findings,
        )
        gate_action = (
            PolicyAction.PASS.value
            if not findings
            else result.pr_action.value
        )
        finding_details = [
            {
                "trace": item.trace,
                "handler_asserted_cwe": item.handler_asserted_cwe,
                "policy_severity": item.policy_severity.value,
            }
            for item in findings
        ]
        gate_cwes = sorted(
            {
                item.handler_asserted_cwe
                for item in findings
                if item.handler_asserted_cwe
            }
        )
        outcomes.append(
            {
                "path": entry.rel_path,
                "virtual_path": path,
                "target_type": entry.target_type,
                "expected_rule_ids": sorted(entry.expected_rule_ids),
                "expected_gate_cwes": sorted(entry.expected_gate_cwes),
                "gate_action": gate_action,
                "gate_cwes": gate_cwes,
                "findings": finding_details,
            }
        )
    return outcomes


def summarize_gate_actions(outcomes: list[dict[str, object]]) -> dict[str, int]:
    counts = {PolicyAction.PASS.value: 0, PolicyAction.FLAG.value: 0, PolicyAction.BLOCK.value: 0}
    for item in outcomes:
        action = str(item["gate_action"])
        counts[action] = counts.get(action, 0) + 1
    return counts


def print_gate_summary(title: str, outcomes: list[dict[str, object]]) -> None:
    counts = summarize_gate_actions(outcomes)
    print(f"\n{title}")
    print(
        f"BLOCK={counts.get(PolicyAction.BLOCK.value, 0)} "
        f"FLAG={counts.get(PolicyAction.FLAG.value, 0)} "
        f"PASS={counts.get(PolicyAction.PASS.value, 0)}"
    )
    clean_blocked = [
        item["path"]
        for item in outcomes
        if not item["expected_rule_ids"]
        and not item["expected_gate_cwes"]
        and item["gate_action"] == PolicyAction.BLOCK.value
    ]
    if clean_blocked:
        print("Clean-labeled files that BLOCK:")
        for path in clean_blocked:
            print(f"  {path}")


def build_report(
    generated: dict,
    holdout: dict,
    parse_coverage: dict[str, dict[str, int | float]],
    handler_baseline: dict,
) -> dict:
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "corpus_version": CORPUS_VERSION,
        "corpus_version_notes": CORPUS_VERSION_NOTES,
        "handler_baseline": handler_baseline,
        "fmc_provider_version": FMC_PROVIDER_VERSION,
        "fmc_provider_schema": str(
            FMC_PROVIDER_SCHEMA_PATH.relative_to(ROOT)
        ),
        "ftd_schema_audit": audit_ftd_rule_schema(),
        "ftd_resolver_schema_audit": audit_ftd_resolver_schema(),
        "rule_gaps": build_rule_gaps(),
        "model_asserted_cwe_unrecognized": unrecognized_model_cwe_tally([]),
        "parse_coverage": parse_coverage,
        "generated_corpus": generated,
        "holdout_corpus": holdout,
    }


def _format_metric(value: float | None) -> str:
    if value is None:
        return "—"
    return f"{value:.4f}"


def print_parse_coverage(parse_coverage: dict[str, dict[str, int | float]]) -> None:
    print("\nParse coverage (both corpora combined; remarks excluded from denominator)")
    print(
        f"{'Target type':<24} {'Parsed':>8} {'Total':>8} {'Remarks':>8} {'Coverage':>28}"
    )
    print("-" * 80)
    for target_type, metrics in sorted(parse_coverage.items()):
        parsed, total, remarks, unit = parse_coverage_line_parts(target_type, metrics)
        ratio = float(metrics["parse_coverage_ratio"])
        coverage, _ = format_parse_coverage_summary(parsed, total, ratio, unit)
        print(
            f"{target_type:<24} "
            f"{parsed:>8} "
            f"{total:>8} "
            f"{remarks:>8} "
            f"{coverage:>28}"
        )


def print_per_rule_table(title: str, per_rule: dict[str, dict]) -> None:
    print(f"\n{title}")
    print(f"{'Rule':<10} {'TP':>4} {'FP':>4} {'FN':>4} {'Precision':>10} {'Recall':>8}")
    print("-" * 50)
    for rule_id in enabled_rule_ids():
        metrics = per_rule.get(
            rule_id,
            {
                "true_positives": 0,
                "false_positives": 0,
                "false_negatives": 0,
                "precision": None,
                "recall": None,
                "false_positive_files": [],
            },
        )
        print(
            f"{rule_id:<10} "
            f"{metrics['true_positives']:>4} "
            f"{metrics['false_positives']:>4} "
            f"{metrics['false_negatives']:>4} "
            f"{_format_metric(metrics['precision']):>10} "
            f"{_format_metric(metrics['recall']):>8}"
        )
    false_positive_rules = [
        rule_id
        for rule_id, metrics in per_rule.items()
        if metrics["false_positives"] > 0
    ]
    if false_positive_rules:
        print("\nFalse positives by rule:")
        for rule_id in sorted(false_positive_rules):
            files = per_rule[rule_id]["false_positive_files"]
            print(f"  {rule_id}: {', '.join(files)}")


def print_ftd_resolver_schema_audit() -> None:
    print(f"\nFTD resolver membership audit (CiscoDevNet/fmc v{FMC_PROVIDER_VERSION})")
    print(f"{'Resource':<22} {'Parser attr':<16} {'In provider':>12} {'Resolver map':>14}")
    print("-" * 68)
    for row in audit_ftd_resolver_schema():
        in_provider = "yes" if row["exists_in_provider"] else "NO"
        in_map = "yes" if row["listed_in_resolver_schema"] else "NO"
        print(
            f"{str(row['resource_type']):<22} "
            f"{str(row['parser_attribute']):<16} "
            f"{in_provider:>12} "
            f"{in_map:>14}"
        )


def print_ftd_schema_audit() -> None:
    print(f"\nFTD schema validity audit (CiscoDevNet/fmc v{FMC_PROVIDER_VERSION})")
    print(f"{'Rule':<10} {'Resource':<22} {'Attribute':<28} {'Exists':>6}")
    print("-" * 70)
    for row in audit_ftd_rule_schema():
        rule_id = str(row["rule_id"])
        for resource in row["resources"]:
            resource_type = str(resource["resource_type"])
            for attr_row in resource["attributes"]:
                exists = "yes" if attr_row["exists_in_provider"] else "NO"
                print(
                    f"{rule_id:<10} {resource_type:<22} "
                    f"{str(attr_row['attribute']):<28} {exists:>6}"
                )


def print_rule_gaps() -> None:
    print("\nRule coverage gaps (not evaluated)")
    print(f"{'Rule':<10} {'CWE':<10} {'Status':<12} Reason")
    print("-" * 72)
    for gap in build_rule_gaps():
        print(
            f"{gap['rule_id']:<10} {gap['cwe']:<10} {gap['status']:<12} {gap['reason']}"
        )


def print_ios_001_reconciliation(
    corpus_name: str,
    corpus_dir: Path,
    entries: list,
) -> tuple[int, int, int]:
    from shift_left.handlers.config.parsers.ios_xe.parser import parse_ios_xe_config
    from shift_left.handlers.config.parsers.ios_xe.resolver import count_ios_001_targets
    from shift_left.handlers.config.parsers.ios_xe_config import match_ios_xe_config_rules

    unparsed_line_count = 0
    unresolvable_ref_count = 0
    ios_001_finding_count = 0

    print(f"\nIOS-001 reconciliation ({corpus_name})")
    print(
        f"{'File':<48} {'Line':>5} {'IOS-001':>8}  Raw text"
    )
    print("-" * 100)

    for entry in entries:
        if entry.target_type != "cisco_ios_xe":
            continue
        content = (corpus_dir / entry.rel_path).read_text()
        parsed = parse_ios_xe_config(content)
        unparsed, unresolvable = count_ios_001_targets(parsed)
        unparsed_line_count += unparsed
        unresolvable_ref_count += unresolvable

        findings = match_ios_xe_config_rules(chunk_content=content, rule_id="IOS-001")
        ios_001_finding_count += len(findings)
        finding_lines = {
            (item.line_start, item.line_end) for item in findings
        }

        for line in parsed.unparsed_lines:
            if line.category != "acl":
                continue
            produced = (line.line_no, line.line_no) in finding_lines
            print(
                f"{entry.rel_path:<48} {line.line_no:>5} "
                f"{'yes' if produced else 'NO':>8}  {line.raw}"
            )

    print(
        f"\nunparsed_line_count={unparsed_line_count} "
        f"unresolvable_ref_count={unresolvable_ref_count} "
        f"ios_001_finding_count={ios_001_finding_count} "
        f"reconciled={'yes' if ios_001_finding_count == unparsed_line_count + unresolvable_ref_count else 'NO'}"
    )
    return unparsed_line_count, unresolvable_ref_count, ios_001_finding_count


def print_rule_suppression_audit() -> None:
    print("\nCross-rule suppression audit")
    print(
        "IOS-001/IOS-010: no suppression (platform mismatch and unparsed ACL lines are independent)."
    )
    print(
        "HCL-001 pre-match: unparseable HCL short-circuits other Terraform rules "
        "(single defect — parser cannot proceed; not dual-defect suppression)."
    )
    print(
        "All other registry rule pairs: independent evaluation loops; no rule skips "
        "another when a sibling fires."
    )


def main() -> int:
    generated_entries = load_corpus(GENERATED_CORPUS_DIR)
    holdout_entries = load_corpus(HOLDOUT_CORPUS_DIR)
    if not generated_entries:
        print(f"No generated corpus entries found under {GENERATED_CORPUS_DIR}", file=sys.stderr)
        return 1
    if not holdout_entries:
        print(f"No holdout corpus entries found under {HOLDOUT_CORPUS_DIR}", file=sys.stderr)
        return 1

    gen_file_results, gen_per_rule = evaluate_corpus(generated_entries, GENERATED_CORPUS_DIR)
    hold_file_results, hold_per_rule = evaluate_corpus(holdout_entries, HOLDOUT_CORPUS_DIR)
    gen_gate_outcomes = evaluate_gate_outcomes(generated_entries, GENERATED_CORPUS_DIR)
    hold_gate_outcomes = evaluate_gate_outcomes(holdout_entries, HOLDOUT_CORPUS_DIR)

    parse_coverage = compute_parse_coverage(generated_entries, holdout_entries)

    generated_report = build_corpus_report(
        corpus_name="generated",
        corpus_dir=GENERATED_CORPUS_DIR,
        entries=generated_entries,
        file_results=gen_file_results,
        per_rule=gen_per_rule,
    )
    holdout_report = build_corpus_report(
        corpus_name="holdout",
        corpus_dir=HOLDOUT_CORPUS_DIR,
        entries=holdout_entries,
        file_results=hold_file_results,
        per_rule=hold_per_rule,
    )
    handler_baseline = build_handler_baseline(
        generated_entries=generated_entries,
        holdout_entries=holdout_entries,
        gen_file_results=gen_file_results,
        hold_file_results=hold_file_results,
        gen_per_rule=gen_per_rule,
        hold_per_rule=hold_per_rule,
    )
    report = build_report(generated_report, holdout_report, parse_coverage, handler_baseline)
    report["gate_outcomes"] = {
        "generated": gen_gate_outcomes,
        "holdout": hold_gate_outcomes,
        "generated_summary": summarize_gate_actions(gen_gate_outcomes),
        "holdout_summary": summarize_gate_actions(hold_gate_outcomes),
    }
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n")

    print(f"Wrote {REPORT_PATH.relative_to(ROOT)}")
    print(
        f"Corpus version: {CORPUS_VERSION} | "
        f"labeled defect instances: {handler_baseline['labeled_defect_instances']}"
    )
    print(
        f"Handler baseline (combined): TP={handler_baseline['true_positives']} "
        f"FP={handler_baseline['false_positives']} "
        f"FN={handler_baseline['false_negatives']} "
        f"recall={handler_baseline['recall']}"
    )
    print(
        f"Generated: {len(generated_entries)} files | "
        f"Holdout: {len(holdout_entries)} files"
    )
    print_parse_coverage(parse_coverage)
    print_per_rule_table("Generated corpus — per-rule metrics", gen_per_rule)
    print_per_rule_table("Holdout corpus — per-rule metrics", hold_per_rule)
    print_gate_summary("Generated corpus — gate outcomes", gen_gate_outcomes)
    print_gate_summary("Holdout corpus — gate outcomes", hold_gate_outcomes)
    print_ios_001_reconciliation("generated", GENERATED_CORPUS_DIR, generated_entries)
    print_ios_001_reconciliation("holdout", HOLDOUT_CORPUS_DIR, holdout_entries)
    print_rule_suppression_audit()
    print_ftd_schema_audit()
    print_ftd_resolver_schema_audit()
    print_rule_gaps()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
