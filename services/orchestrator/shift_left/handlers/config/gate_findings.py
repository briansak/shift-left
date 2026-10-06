"""Build gate-level findings from corpus evaluation (registry rules + scope)."""

from __future__ import annotations

from collections.abc import Sequence

from shift_left.config import AppConfig, ManagedTargetConfig
from shift_left.diff.extractor import ChangedFile
from shift_left.handlers.config.parser_scope import (
    TARGET_TYPE_PARSER_GLOBS,
    path_in_target_parser_scope,
)
from shift_left.routing.globmatch import matches_any
from shift_left.handlers.config.registry_matching import (
    RegistryRuleMatch,
    match_registry_rules,
    registry_rule_line_set_for_path,
)
from shift_left.handlers.config.rules.registry import (
    UNDECLARED_TARGET_TYPE,
    ALL_RULES,
    rule_registry_enforced,
)
from shift_left.handlers.unclaimed_files import findings_for_unclaimed_paths
from shift_left.models.schema import Finding, FindingSource, LineRange, TargetKind
from shift_left.policy.severity import apply_policy_severities

_REGISTRY_RULE_IDS = frozenset(
    rule.id for rule in ALL_RULES if rule_registry_enforced(rule)
)


def registry_rule_lines_from_findings(findings: list[Finding]) -> frozenset[tuple[str, int]]:
    """(rule_id, line_start) pairs encoded in handler registry findings."""
    lines: set[tuple[str, int]] = set()
    for finding in findings:
        if finding.source != FindingSource.HANDLER:
            continue
        if not finding.trace or not finding.trace.startswith("handler:"):
            continue
        rule_id = finding.trace.removeprefix("handler:")
        if rule_id not in _REGISTRY_RULE_IDS:
            continue
        lines.add((rule_id, finding.line_range.start))
    return frozenset(lines)


def _finding_from_registry_match(
    match: RegistryRuleMatch,
    *,
    path: str,
    repo: str,
    pr_ref: str,
    commit_sha: str,
) -> Finding:
    return Finding(
        source=FindingSource.HANDLER,
        target_kind=TargetKind.CONFIG,
        repo=repo,
        pr_ref=pr_ref,
        commit_sha=commit_sha,
        file_path=path,
        line_range=LineRange(start=match.line_start, end=match.line_end),
        handler_asserted_cwe=match.cwe,
        title=match.title or f"Deterministic rule: {match.rule_id}",
        description=match.description or match.pattern_id,
        trace=f"handler:{match.rule_id}",
        construct_key=match.construct_key or None,
    )


def findings_for_corpus_file(
    *,
    path: str,
    target_type: str,
    content: str,
    repo: str = "eval/corpus",
    pr_ref: str = "eval",
    commit_sha: str = "eval",
    config: AppConfig | None = None,
) -> list[Finding]:
    """Synthesize handler findings for gate simulation on a labeled corpus file."""
    app_config = config or AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": "/tmp/shift-left-eval-gate.db"},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        }
    )
    findings: list[Finding] = []

    if target_type == UNDECLARED_TARGET_TYPE:
        for match in match_registry_rules(target_type, content):
            findings.append(
                _finding_from_registry_match(
                    match,
                    path=path,
                    repo=repo,
                    pr_ref=pr_ref,
                    commit_sha=commit_sha,
                )
            )
        return apply_policy_severities(findings, app_config)

    if not path_in_target_parser_scope(target_type, path):
        findings.extend(
            findings_for_unclaimed_paths(
                [path],
                gate=app_config.gate.unclaimed_files,
                repo=repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
            )
        )
    else:
        for match in match_registry_rules(target_type, content):
            findings.append(
                _finding_from_registry_match(
                    match,
                    path=path,
                    repo=repo,
                    pr_ref=pr_ref,
                    commit_sha=commit_sha,
                )
            )

    return apply_policy_severities(findings, app_config)


def _matching_targets(
    path: str,
    repo: str,
    targets: Sequence[ManagedTargetConfig],
) -> list[ManagedTargetConfig]:
    return [
        target
        for target in targets
        if target.repo == repo
        if any(matches_any(path, [pattern]) for pattern in target.config_paths)
    ]


def resolve_config_target_type(
    path: str,
    content: str,
    *,
    repo: str,
    targets: Sequence[ManagedTargetConfig],
) -> str | None:
    """Resolve managed-target type for a config path (explicit target or parser-scope inference)."""
    matched_targets = _matching_targets(path, repo, targets)
    if len(matched_targets) == 1:
        return matched_targets[0].target_type
    if len(matched_targets) > 1:
        return None

    candidates = [
        target_type
        for target_type in TARGET_TYPE_PARSER_GLOBS
        if path_in_target_parser_scope(target_type, path)
    ]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    if "cisco_ftd" in candidates and "generic_terraform" in candidates:
        if 'resource "fmc_' in content or 'provider "fmc"' in content:
            return "cisco_ftd"
        return "generic_terraform"
    return candidates[0]


def _changed_file_content(changed: ChangedFile) -> str:
    """Reconstruct new-side file text from unified-diff hunks (drop ``+/-/ `` prefixes)."""
    lines: list[str] = []
    for hunk in changed.hunks:
        for raw in hunk.content.splitlines():
            if raw.startswith("... ["):
                continue
            if not raw:
                lines.append("")
                continue
            mark = raw[0]
            text = raw[1:] if mark in "+- " else raw
            if mark == "-":
                continue
            lines.append(text)
    return "\n".join(lines)


def findings_from_config_handlers(
    files: list[ChangedFile],
    *,
    repo: str,
    pr_ref: str,
    commit_sha: str,
    targets: Sequence[ManagedTargetConfig],
    config: AppConfig | None = None,
) -> list[Finding]:
    """Deterministic config handler findings for PR diff hunks (no model invocation)."""
    app_config = config or AppConfig.model_validate(
        {
            "findings_store": {"sqlite_path": "/tmp/shift-left-eval-gate.db"},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        }
    )
    findings: list[Finding] = []

    for changed in files:
        path = changed.path
        content = _changed_file_content(changed)
        target_type = resolve_config_target_type(path, content, repo=repo, targets=targets)
        if target_type is None:
            continue
        findings.extend(
            findings_for_corpus_file(
                path=path,
                target_type=target_type,
                content=content,
                repo=repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
                config=app_config,
            )
        )

    return findings


__all__ = [
    "findings_for_corpus_file",
    "findings_from_config_handlers",
    "registry_rule_line_set_for_path",
    "registry_rule_lines_from_findings",
    "resolve_config_target_type",
]
