"""PR gate findings for changed files outside declared review scope."""

from __future__ import annotations

from shift_left.config import UnclaimedFilesGateConfig
from shift_left.models.schema import Finding, FindingSource, LineRange, Severity, TargetKind
from shift_left.policy.construct_key import file_scope

UNCLAIMED_TRACE = "handler:unclaimed-file"


def findings_for_unclaimed_paths(
    paths: list[str],
    *,
    gate: UnclaimedFilesGateConfig,
    repo: str,
    pr_ref: str,
    commit_sha: str,
) -> list[Finding]:
    if not gate.enabled or not paths:
        return []

    findings: list[Finding] = []
    for path in sorted(paths):
        findings.append(
            Finding(
                source=FindingSource.HANDLER,
                target_kind=TargetKind.CONFIG,
                repo=repo,
                pr_ref=pr_ref,
                commit_sha=commit_sha,
                file_path=path,
                line_range=LineRange(start=1, end=1),
                handler_asserted_cwe=gate.handler_asserted_cwe,
                model_asserted_severity=Severity.HIGH,
                confidence=1.0,
                title="Changed file outside declared review scope",
                construct_key=file_scope(),
                description=(
                    f"{path} is not matched by routing.code_globs or routing.config_globs "
                    "and is not listed in routing.pr_gate_exclusion_globs. "
                    "Add a glob claim or an explicit gate exclusion."
                ),
                trace=UNCLAIMED_TRACE,
            )
        )
    return findings
