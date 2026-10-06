"""Gate regression on labeled config corpora."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from shift_left.config import RoutingConfig
from shift_left.handlers.config.parser_scope import path_in_target_parser_scope
from shift_left.handlers.config.registry_matching import match_registry_rules
from shift_left.models.schema import PolicyAction
from shift_left.routing.path_claim import PathClaim, classify_path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from validation.eval_handlers import (  # noqa: E402
    GENERATED_CORPUS_DIR,
    HOLDOUT_CORPUS_DIR,
    evaluate_gate_outcomes,
    load_corpus,
)


def test_cfg_outside_parser_scope_is_unclaimed() -> None:
    routing = RoutingConfig()
    path = "firewall/bootstrap.cfg"
    assert not path_in_target_parser_scope("cisco_secure_firewall", path)
    assert classify_path(path, routing) == PathClaim.UNCLAIMED


def test_rules_file_in_parser_scope_is_config_claim() -> None:
    routing = RoutingConfig()
    assert classify_path("firewall/edge.rules", routing) == PathClaim.CONFIG


def test_expected_labeled_corpus_files_do_not_pass_gate() -> None:
    for corpus_dir in (GENERATED_CORPUS_DIR, HOLDOUT_CORPUS_DIR):
        entries = load_corpus(corpus_dir)
        outcomes = evaluate_gate_outcomes(entries, corpus_dir)
        for entry, outcome in zip(entries, outcomes, strict=True):
            if not entry.expected_rule_ids and not entry.expected_gate_cwes:
                continue
            assert outcome["gate_action"] != PolicyAction.PASS.value, entry.rel_path


def test_clean_labeled_corpus_files_pass_gate() -> None:
    for corpus_dir in (GENERATED_CORPUS_DIR, HOLDOUT_CORPUS_DIR):
        entries = load_corpus(corpus_dir)
        outcomes = evaluate_gate_outcomes(entries, corpus_dir)
        for entry, outcome in zip(entries, outcomes, strict=True):
            if entry.expected_rule_ids:
                continue
            if entry.expected_gate_cwes:
                continue
            assert outcome["gate_action"] == PolicyAction.PASS.value, entry.rel_path


def test_expected_gate_cwes_present_in_findings() -> None:
    entries = load_corpus(HOLDOUT_CORPUS_DIR)
    outcomes = evaluate_gate_outcomes(entries, HOLDOUT_CORPUS_DIR)
    by_path = {item["path"]: item for item in outcomes}
    cfg = "cisco_secure_firewall/holdout-asa-nonrules-cfg.cfg"
    assert by_path[cfg]["gate_action"] == PolicyAction.BLOCK.value
    assert by_path[cfg]["gate_cwes"] == ["CWE-657"]


def test_corpus_per_rule_false_positive_count_is_zero() -> None:
    """Finding-level guard: every registry match must be labeled (no silent FPs)."""
    failures: list[str] = []
    for corpus_name, corpus_dir in (
        ("generated", GENERATED_CORPUS_DIR),
        ("holdout", HOLDOUT_CORPUS_DIR),
    ):
        for entry in load_corpus(corpus_dir):
            content = (corpus_dir / entry.rel_path).read_text()
            expected = set(entry.expected_rule_ids)
            for match in match_registry_rules(entry.target_type, content):
                if match.rule_id in expected:
                    continue
                failures.append(
                    f"{corpus_name}:{entry.rel_path}:{match.rule_id}:line {match.line_start}"
                )
    assert not failures, "per-rule false positives:\n" + "\n".join(sorted(failures))


def test_every_enabled_registry_rule_has_generated_and_holdout_fixture() -> None:
    """Each evaluated rule needs 2+2 generated (positive+negative) and >=1 holdout positive."""
    from shift_left.handlers.config.rules.registry import ALL_RULES, Rule, rule_requires_fixture_coverage

    def fixture_target_types(rule: Rule) -> frozenset[str]:
        if rule.id == "HCL-001":
            return frozenset({"generic_terraform", "cisco_ftd"})
        return frozenset({rule.target_type})

    def count_fixture_coverage(
        corpus_dir: Path,
    ) -> tuple[dict[str, int], dict[str, int]]:
        positives: dict[str, int] = {}
        negatives: dict[str, int] = {}
        for entry in load_corpus(corpus_dir):
            content = (corpus_dir / entry.rel_path).read_text()
            matched = {
                match.rule_id
                for match in match_registry_rules(entry.target_type, content)
            }
            for rule in ALL_RULES:
                if not rule_requires_fixture_coverage(rule):
                    continue
                if rule.id == "CLI-001":
                    if entry.target_type != "undeclared":
                        continue
                    emitted = rule.id in matched
                    if rule.id in entry.expected_rule_ids and emitted:
                        positives[rule.id] = positives.get(rule.id, 0) + 1
                    elif rule.id not in entry.expected_rule_ids and not emitted:
                        negatives[rule.id] = negatives.get(rule.id, 0) + 1
                    continue
                if entry.target_type not in fixture_target_types(rule):
                    continue
                if rule.id in entry.expected_rule_ids:
                    positives[rule.id] = positives.get(rule.id, 0) + 1
                elif rule.id not in matched:
                    negatives[rule.id] = negatives.get(rule.id, 0) + 1
        return positives, negatives

    enabled = [rule.id for rule in ALL_RULES if rule_requires_fixture_coverage(rule)]
    gen_pos, gen_neg = count_fixture_coverage(GENERATED_CORPUS_DIR)
    hold_pos, _hold_neg = count_fixture_coverage(HOLDOUT_CORPUS_DIR)

    failures: list[str] = []
    for rule_id in enabled:
        if gen_pos.get(rule_id, 0) < 2:
            failures.append(
                f"{rule_id}: generated positives {gen_pos.get(rule_id, 0)} (need >= 2)"
            )
        if gen_neg.get(rule_id, 0) < 2:
            failures.append(
                f"{rule_id}: generated negatives {gen_neg.get(rule_id, 0)} (need >= 2)"
            )
        if hold_pos.get(rule_id, 0) < 1:
            failures.append(
                f"{rule_id}: holdout positives {hold_pos.get(rule_id, 0)} (need >= 1)"
            )
    assert not failures, "registry rule fixture coverage:\n" + "\n".join(failures)
