"""Policy engine unit tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from shift_left.config import AppConfig, PolicyConfig
from shift_left.models.schema import (
    Finding,
    FindingSource,
    LineRange,
    Policy,
    PolicyAction,
    PolicyAppliesTo,
    PolicyRule,
    PolicySeverity,
    Severity,
    TargetKind,
)
from shift_left.policy.engine import PolicyEngine
from shift_left.policy.loader import PolicyValidationError, load_and_validate_policies
from shift_left.policy.severity import apply_policy_severities, derive_policy_severity

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from validation.eval_handlers import (  # noqa: E402
    GENERATED_CORPUS_DIR,
    HOLDOUT_CORPUS_DIR,
    _default_eval_config,
    load_corpus,
)
from shift_left.handlers.config.gate_findings import findings_for_corpus_file  # noqa: E402


def _finding(
    *,
    handler_cwe: str | None = "CWE-89",
    model_cwe: str | None = "CWE-89",
    path: str = "app/db.py",
    trace: str | None = None,
) -> Finding:
    finding = Finding(
        source=FindingSource.ANTARES,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="aaa",
        file_path=path,
        line_range=LineRange(start=1, end=1),
        model_asserted_cwe=model_cwe,
        handler_asserted_cwe=handler_cwe,
        model_asserted_severity=Severity.LOW,
        confidence=0.9,
        title="Test",
        description="Test finding",
        trace=trace,
    )
    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    return apply_policy_severities([finding], config)[0]


def test_block_threshold_produces_block_decision() -> None:
    config = PolicyConfig(
        default_action=PolicyAction.FLAG,
        rules=[
            Policy(
                id="block-critical-code",
                name="Block critical code",
                applies_to=PolicyAppliesTo(target_kind=TargetKind.CODE, path_globs=["**/*"]),
                rules=[PolicyRule(severity_threshold=PolicySeverity.CRITICAL)],
                action=PolicyAction.BLOCK,
            )
        ],
    )
    engine = PolicyEngine(config)
    finding = _finding(handler_cwe="CWE-502", model_cwe="CWE-502")
    assert finding.policy_severity == PolicySeverity.CRITICAL
    result = engine.evaluate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="aaa",
        findings=[finding],
    )
    assert result.pr_action == PolicyAction.BLOCK
    assert result.pr_decision.finding_decisions[0].matched_policy_id == "block-critical-code"


def test_policy_decisions_are_deterministic() -> None:
    config = PolicyConfig(
        rules=[
            Policy(
                id="flag-high",
                name="Flag high",
                applies_to=PolicyAppliesTo(target_kind=TargetKind.CODE, path_globs=["**/*.py"]),
                rules=[PolicyRule(severity_threshold=PolicySeverity.HIGH)],
                action=PolicyAction.FLAG,
            )
        ],
    )
    engine = PolicyEngine(config)
    findings = [_finding(handler_cwe="CWE-89", model_cwe="CWE-89")]
    assert findings[0].policy_severity == PolicySeverity.HIGH
    first = engine.evaluate(repo="o/r", pr_ref="PR-1", commit_sha="aaa", findings=findings)
    second = engine.evaluate(repo="o/r", pr_ref="PR-1", commit_sha="aaa", findings=findings)
    assert first.pr_decision.model_dump() == second.pr_decision.model_dump()


def test_unclassified_uses_default_action() -> None:
    config = PolicyConfig(default_action=PolicyAction.PASS)
    engine = PolicyEngine(config)
    finding = Finding(
        source=FindingSource.ANTARES,
        target_kind=TargetKind.CODE,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="aaa",
        file_path="readme.md",
        model_asserted_severity=Severity.CRITICAL,
        policy_severity=PolicySeverity.UNCLASSIFIED,
        confidence=0.9,
        title="T",
        description="D",
    )
    result = engine.evaluate(repo="o/r", pr_ref="PR-1", commit_sha="aaa", findings=[finding])
    assert result.pr_action == PolicyAction.PASS
    assert "unclassified" in result.pr_decision.finding_decisions[0].explanation.lower()


def test_unclassified_never_blocks_under_block_default_or_policy() -> None:
    config = PolicyConfig(
        default_action=PolicyAction.BLOCK,
        rules=[
            Policy(
                id="block-all-config",
                name="Block all config",
                applies_to=PolicyAppliesTo(target_kind=TargetKind.CONFIG, path_globs=["**/*"]),
                rules=[PolicyRule(severity_threshold=PolicySeverity.LOW)],
                action=PolicyAction.BLOCK,
            )
        ],
    )
    engine = PolicyEngine(config)
    finding = Finding(
        source=FindingSource.FOUNDATION_SEC,
        target_kind=TargetKind.CONFIG,
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="aaa",
        file_path="terraform/insecure.tf",
        model_asserted_cwe="CWE-20",
        model_asserted_severity=Severity.HIGH,
        policy_severity=PolicySeverity.UNCLASSIFIED,
        confidence=0.9,
        title="Model only",
        description="No handler rule",
    )
    result = engine.evaluate(repo="o/r", pr_ref="PR-1", commit_sha="aaa", findings=[finding])
    assert result.pr_decision.finding_decisions[0].decision == PolicyAction.FLAG
    assert result.pr_action == PolicyAction.FLAG


def test_policy_rule_rejects_model_asserted_severity_field() -> None:
    with pytest.raises(ValidationError):
        PolicyRule(
            severity_threshold=PolicySeverity.HIGH,
            model_asserted_severity=Severity.HIGH,  # type: ignore[call-arg]
        )


def test_malformed_policy_fails_loud_at_startup() -> None:
    config = PolicyConfig(
        rules=[
            Policy(
                id="",
                name="bad",
                applies_to=PolicyAppliesTo(path_globs=["**/*"]),
                rules=[PolicyRule()],
                action=PolicyAction.FLAG,
            )
        ],
    )
    with pytest.raises(PolicyValidationError):
        load_and_validate_policies(config)


def test_human_review_required_cannot_be_disabled() -> None:
    config = PolicyConfig(human_review_required=False)
    with pytest.raises(PolicyValidationError, match="auto-approve"):
        load_and_validate_policies(config)


def test_config_scoped_thresholds_by_target_kind() -> None:
    config = PolicyConfig(
        rules=[
            Policy(
                id="block-config-critical",
                name="Block critical config",
                applies_to=PolicyAppliesTo(target_kind=TargetKind.CONFIG, path_globs=["**/*"]),
                rules=[PolicyRule(severity_threshold=PolicySeverity.HIGH)],
                action=PolicyAction.BLOCK,
            ),
            Policy(
                id="flag-code-high",
                name="Flag high code",
                applies_to=PolicyAppliesTo(target_kind=TargetKind.CODE, path_globs=["**/*"]),
                rules=[PolicyRule(severity_threshold=PolicySeverity.HIGH)],
                action=PolicyAction.FLAG,
            ),
        ],
    )
    engine = PolicyEngine(config)
    code_result = engine.evaluate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="aaa",
        findings=[_finding(handler_cwe="CWE-89", model_cwe="CWE-89", path="app/db.py")],
    )
    config_finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.FOUNDATION_SEC,
                target_kind=TargetKind.CONFIG,
                repo="o/r",
                pr_ref="PR-1",
                commit_sha="aaa",
                file_path="infra/main.tf",
                handler_asserted_cwe="CWE-284",
                model_asserted_cwe="CWE-20",
                model_asserted_severity=Severity.LOW,
                confidence=0.9,
                title="Config issue",
                description="Test",
            )
        ],
        AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}}),
    )[0]
    config_result = engine.evaluate(
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="aaa",
        findings=[config_finding],
    )
    assert code_result.pr_action == PolicyAction.FLAG
    assert config_result.pr_action == PolicyAction.BLOCK


def test_cwe754_policy_covers_blocking_policy_path_globs() -> None:
    from shift_left.handlers.config.parser_scope import BLOCKING_POLICY_PATH_GLOBS

    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    policy = next(p for p in config.policy.rules if p.id == "block-uninterpretable-config")
    globs = set(policy.applies_to.path_globs)
    assert globs == set(BLOCKING_POLICY_PATH_GLOBS)
    ingress = next(p for p in config.policy.rules if p.id == "block-unrestricted-ingress")
    assert set(ingress.applies_to.path_globs) == set(BLOCKING_POLICY_PATH_GLOBS)


@pytest.mark.parametrize("target_type", sorted(__import__(
    "shift_left.handlers.config.parser_scope", fromlist=["TARGET_TYPE_PARSER_GLOBS"]
).TARGET_TYPE_PARSER_GLOBS))
def test_cwe754_blocks_on_every_parser_scoped_target_type(target_type: str) -> None:
    from shift_left.handlers.config.parser_scope import TARGET_TYPE_PARSER_GLOBS

    glob = TARGET_TYPE_PARSER_GLOBS[target_type][0]
    suffix = glob.rsplit(".", 1)[-1]
    path = f"configs/device.{suffix}" if suffix != "*" else "configs/device"
    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.HANDLER,
                target_kind=TargetKind.CONFIG,
                repo="org/repo",
                pr_ref="PR-1",
                commit_sha="deadbeef",
                file_path=path,
                line_range=LineRange(start=1, end=1),
                handler_asserted_cwe="CWE-754",
                title="Uninterpretable config",
                description="Test",
                trace="handler:TEST-754",
            )
        ],
        config,
    )[0]
    assert finding.policy_severity == PolicySeverity.HIGH
    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        findings=[finding],
    )
    assert result.pr_action == PolicyAction.BLOCK


_BLOCKING_POLICY_SEVERITIES = frozenset({PolicySeverity.HIGH, PolicySeverity.CRITICAL})

# Pre-fix gate failures before registry-severity merge (both corpora):
# Block registry + no CWE policy → FLAG: 10 generated + 3 holdout single-rule files.
# Flag registry + CWE-284 policy → BLOCK: 3 generated ASA-002 + 1 holdout ASA-002
#   + 1 generated co-occurrence (edge-unbounded-ports.tf: FTD-002 caps FTD-003 file).
_PRE_FIX_BLOCK_GATE_FAILURES = (
    "FTD-004",
    "IOS-002",
    "IOS-004",
    "IOS-005",
    "ASA-004",
)
_PRE_FIX_FLAG_GATE_FAILURES = ("ASA-002", "FTD-002")

_TARGET_PATH_SUFFIX = {
    "cisco_ios_xe": "device.cfg",
    "cisco_secure_firewall": "device.rules",
    "cisco_ftd": "device.tf",
    "generic_terraform": "device.tf",
}


def _single_rule_corpus_by_id() -> dict[str, tuple[Path, object]]:
    """Map rule id → (corpus_dir, entry) for files labeled with exactly one rule."""
    by_id: dict[str, tuple[Path, object]] = {}
    for corpus_dir in (GENERATED_CORPUS_DIR, HOLDOUT_CORPUS_DIR):
        for entry in load_corpus(corpus_dir):
            expected = set(entry.expected_rule_ids)
            if len(expected) != 1:
                continue
            rule_id = next(iter(expected))
            by_id.setdefault(rule_id, (corpus_dir, entry))
    return by_id


def _gate_action_for_rule_finding(
    *,
    rule_id: str,
    corpus_dir: Path | None,
    entry,
    config: AppConfig,
) -> PolicyAction:
    engine = PolicyEngine(config.policy)
    if corpus_dir is not None and entry is not None:
        content = (corpus_dir / entry.rel_path).read_text()
        findings = apply_policy_severities(
            findings_for_corpus_file(
                path=entry.virtual_path,
                target_type=entry.target_type,
                content=content,
                config=config,
            ),
            config,
        )
        rule_findings = [f for f in findings if f.trace == f"handler:{rule_id}"]
        assert rule_findings, f"{entry.rel_path} produced no finding for {rule_id}"
        findings = rule_findings
    else:
        from shift_left.handlers.config.rules.registry import rule_by_id

        rule = rule_by_id(rule_id)
        assert rule is not None
        path = _TARGET_PATH_SUFFIX.get(rule.target_type, "device.cfg")
        finding = Finding(
            source=FindingSource.HANDLER,
            target_kind=TargetKind.CONFIG,
            repo="org/repo",
            pr_ref="PR-1",
            commit_sha="deadbeef",
            file_path=path,
            line_range=LineRange(start=1, end=1),
            handler_asserted_cwe=rule.cwe,
            title="t",
            description="d",
            trace=f"handler:{rule_id}",
        )
        findings = apply_policy_severities([finding], config)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        findings=findings,
    )
    return result.pr_action


def _block_registry_rule_ids() -> list[str]:
    from shift_left.handlers.config.rules.registry import ALL_RULES, rule_requires_fixture_coverage

    return [
        rule.id
        for rule in ALL_RULES
        if rule_requires_fixture_coverage(rule) and rule.severity == "block"
    ]


def _flag_registry_rule_ids() -> list[str]:
    from shift_left.handlers.config.rules.registry import ALL_RULES, rule_requires_fixture_coverage

    return [
        rule.id
        for rule in ALL_RULES
        if rule_requires_fixture_coverage(rule) and rule.severity == "flag"
    ]


@pytest.mark.parametrize("rule_id", _block_registry_rule_ids())
def test_enabled_block_registry_rules_gate_block(rule_id: str) -> None:
    """Every enabled block registry rule must gate BLOCK on a single-violation corpus file."""
    config = _default_eval_config()
    corpus = _single_rule_corpus_by_id()
    corpus_dir, entry = corpus.get(rule_id, (None, None))
    if corpus_dir is None:
        pytest.fail(f"no single-rule corpus file for block registry rule {rule_id}")
    action = _gate_action_for_rule_finding(
        rule_id=rule_id,
        corpus_dir=corpus_dir,
        entry=entry,
        config=config,
    )
    assert action == PolicyAction.BLOCK, (
        f"{rule_id} via {entry.rel_path}: expected BLOCK, got {action.value}"
    )


@pytest.mark.parametrize("rule_id", _flag_registry_rule_ids())
def test_enabled_flag_registry_rules_gate_flag_not_block(rule_id: str) -> None:
    """Every enabled flag registry rule must gate FLAG (never BLOCK)."""
    config = _default_eval_config()
    corpus = _single_rule_corpus_by_id()
    corpus_dir, entry = corpus.get(rule_id, (None, None))
    action = _gate_action_for_rule_finding(
        rule_id=rule_id,
        corpus_dir=corpus_dir,
        entry=entry,
        config=config,
    )
    assert action == PolicyAction.FLAG, (
        f"{rule_id}: expected FLAG, got {action.value}"
        + (f" ({entry.rel_path})" if entry is not None else " (synthetic)")
    )
    assert action != PolicyAction.BLOCK


def test_enabled_block_registry_rules_resolve_to_blocking_policy_severity() -> None:
    """Block registry rules must map to HIGH/CRITICAL policy_severity (CWE guard)."""
    from shift_left.handlers.config.rules.registry import ALL_RULES, rule_requires_fixture_coverage

    config = AppConfig.model_validate({"findings_store": {"sqlite_path": "/tmp/x.db"}})
    failures: list[str] = []
    for rule in ALL_RULES:
        if not rule_requires_fixture_coverage(rule) or rule.severity != "block":
            continue
        finding = Finding(
            source=FindingSource.HANDLER,
            target_kind=TargetKind.CONFIG,
            repo="org/repo",
            pr_ref="PR-1",
            commit_sha="deadbeef",
            file_path="configs/device.cfg",
            line_range=LineRange(start=1, end=1),
            handler_asserted_cwe=rule.cwe,
            title="t",
            description="d",
            trace=f"handler:{rule.id}",
        )
        severity = derive_policy_severity(finding, config)
        if severity not in _BLOCKING_POLICY_SEVERITIES:
            failures.append(f"{rule.id} ({rule.cwe} -> {severity.value})")
    assert not failures, "block registry rules with non-blocking policy_severity:\n" + "\n".join(
        failures
    )


def test_registry_block_finding_records_registry_decision_source() -> None:
    config = _default_eval_config()
    corpus = _single_rule_corpus_by_id()
    corpus_dir, entry = corpus["IOS-002"]
    content = (corpus_dir / entry.rel_path).read_text()
    findings = apply_policy_severities(
        findings_for_corpus_file(
            path=entry.virtual_path,
            target_type=entry.target_type,
            content=content,
            config=config,
        ),
        config,
    )
    rule_findings = [f for f in findings if f.trace == "handler:IOS-002"]
    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        findings=rule_findings,
    )
    decision = result.pr_decision.finding_decisions[0]
    assert decision.decision == PolicyAction.BLOCK
    assert decision.matched_policy_id == "registry:IOS-002"


def test_broad_cwe_policy_does_not_escalate_flag_registry_asa_002() -> None:
    config = _default_eval_config()
    finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.HANDLER,
                target_kind=TargetKind.CONFIG,
                repo="org/repo",
                pr_ref="PR-1",
                commit_sha="deadbeef",
                file_path="firewall/objects.rules",
                line_range=LineRange(start=1, end=1),
                handler_asserted_cwe="CWE-284",
                title="Broad service object",
                description="Test",
                trace="handler:ASA-002",
            )
        ],
        config,
    )[0]
    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        findings=[finding],
    )
    decision = result.pr_decision.finding_decisions[0]
    assert decision.decision == PolicyAction.FLAG
    assert decision.matched_policy_id == "registry:ASA-002"
    assert decision.matched_policy_id != "block-unrestricted-ingress"


def test_operator_escalation_raises_flag_registry_to_block() -> None:
    from shift_left.models.schema import OperatorEscalation

    base = _default_eval_config()
    config = base.model_copy(
        update={
            "policy": base.policy.model_copy(
                update={
                    "operator_escalations": [
                        OperatorEscalation(rule_id="ASA-002", action=PolicyAction.BLOCK)
                    ]
                }
            )
        }
    )
    finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.HANDLER,
                target_kind=TargetKind.CONFIG,
                repo="org/repo",
                pr_ref="PR-1",
                commit_sha="deadbeef",
                file_path="firewall/objects.rules",
                line_range=LineRange(start=1, end=1),
                handler_asserted_cwe="CWE-284",
                title="Broad service object",
                description="Test",
                trace="handler:ASA-002",
            )
        ],
        config,
    )[0]
    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        findings=[finding],
    )
    decision = result.pr_decision.finding_decisions[0]
    assert decision.decision == PolicyAction.BLOCK
    assert decision.matched_policy_id == "operator-escalation:ASA-002"


def test_block_registry_rule_cannot_be_downgraded_by_default_action() -> None:
    config = _default_eval_config()
    corpus = _single_rule_corpus_by_id()
    corpus_dir, entry = corpus["IOS-002"]
    action = _gate_action_for_rule_finding(
        rule_id="IOS-002",
        corpus_dir=corpus_dir,
        entry=entry,
        config=config,
    )
    assert action == PolicyAction.BLOCK


def test_cwe_657_unclaimed_finding_blocks_via_operator_policy() -> None:
    config = _default_eval_config()
    finding = apply_policy_severities(
        [
            Finding(
                source=FindingSource.HANDLER,
                target_kind=TargetKind.CONFIG,
                repo="org/repo",
                pr_ref="PR-1",
                commit_sha="deadbeef",
                file_path="firewall/bootstrap.cfg",
                line_range=LineRange(start=1, end=1),
                handler_asserted_cwe="CWE-657",
                title="Unclaimed path",
                description="Test",
                trace="handler:unclaimed-file",
            )
        ],
        config,
    )[0]
    engine = PolicyEngine(config.policy)
    result = engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="deadbeef",
        findings=[finding],
    )
    decision = result.pr_decision.finding_decisions[0]
    assert decision.decision == PolicyAction.BLOCK
    assert decision.matched_policy_id == "block-unclaimed-changed-files"


def test_every_block_finding_in_corpus_has_decision_source() -> None:
    """BLOCK findings must carry matched_policy_id for audit provenance."""
    config = _default_eval_config()
    engine = PolicyEngine(config.policy)
    failures: list[str] = []
    for corpus_name, corpus_dir in (
        ("generated", GENERATED_CORPUS_DIR),
        ("holdout", HOLDOUT_CORPUS_DIR),
    ):
        for entry in load_corpus(corpus_dir):
            content = (corpus_dir / entry.rel_path).read_text()
            findings = apply_policy_severities(
                findings_for_corpus_file(
                    path=entry.virtual_path,
                    target_type=entry.target_type,
                    content=content,
                    config=config,
                ),
                config,
            )
            if not findings:
                continue
            result = engine.evaluate(
                repo="org/repo",
                pr_ref="PR-1",
                commit_sha="deadbeef",
                findings=findings,
            )
            for item in result.pr_decision.finding_decisions:
                if item.decision != PolicyAction.BLOCK:
                    continue
                if not item.matched_policy_id:
                    failures.append(f"{corpus_name}:{entry.rel_path}:{item.finding_id}")
    assert not failures, "BLOCK findings missing decision source:\n" + "\n".join(failures)
