"""Eval harness and PR gate must produce identical registry rule matches."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shift_left.config import ManagedTargetConfig  # noqa: E402
from shift_left.diff.config_extractor import parse_config_diff  # noqa: E402
from shift_left.diff.extractor import ChangedFile, ChangedHunk  # noqa: E402
from shift_left.handlers.config.gate_findings import (  # noqa: E402
    findings_for_corpus_file,
    findings_from_config_handlers,
    registry_rule_lines_from_findings,
)
from shift_left.handlers.config.parser_scope import path_in_target_parser_scope  # noqa: E402
from shift_left.handlers.config.registry_matching import registry_rule_line_set_for_path  # noqa: E402
from shift_left.routing.path_claim import PathClaim, classify_path  # noqa: E402
from shift_left.routing.router import route_changes  # noqa: E402
from validation.eval_handlers import (  # noqa: E402
    GENERATED_CORPUS_DIR,
    HOLDOUT_CORPUS_DIR,
    _default_eval_config,
    load_corpus,
)

_CORPUS_TARGET_TYPES = frozenset(
    {
        "cisco_secure_firewall",
        "cisco_ios_xe",
        "cisco_nx_os",
        "cisco_ftd",
        "generic_terraform",
    },
)
_CORPUS_REPO = "eval/corpus"


def _corpus_managed_target(entry) -> ManagedTargetConfig:
    return ManagedTargetConfig(
        id=f"corpus-{entry.target_type}",
        display_name=entry.target_type,
        target_type=entry.target_type,
        repo=_CORPUS_REPO,
        config_paths=["**/*"],
    )


def _handler_rule_lines(findings) -> frozenset[tuple[str, int]]:
    lines: set[tuple[str, int]] = set()
    for finding in findings:
        trace = finding.trace or ""
        if not trace.startswith("handler:"):
            continue
        lines.add((trace.removeprefix("handler:"), finding.line_range.start))
    return frozenset(lines)


def _corpus_changed_file(entry, content: str) -> ChangedFile:
    """ChangedFile shaped like ``parse_unified_diff`` (``+``-prefixed new-side lines)."""
    lines = content.splitlines()
    line_count = max(1, len(lines))
    prefixed = "\n".join(f"+{line}" for line in lines)
    return ChangedFile(
        path=entry.virtual_path,
        hunks=[
            ChangedHunk(
                entry.virtual_path,
                1,
                1,
                line_count,
                prefixed,
                True,
                False,
            )
        ],
        is_new_file=True,
        is_deleted=False,
    )


def _synthetic_add_file_diff(path: str, content: str) -> str:
    """Unified diff that adds ``content`` as a new file at ``path`` (PR-shaped)."""
    lines = content.splitlines()
    n = len(lines)
    if n == 0:
        hunk = "@@ -0,0 +0,0 @@\n"
        body = ""
    elif n == 1:
        hunk = "@@ -0,0 +1 @@\n"
        body = f"+{lines[0]}\n"
    else:
        hunk = f"@@ -0,0 +1,{n} @@\n"
        body = "".join(f"+{line}\n" for line in lines)
    return (
        f"diff --git a/{path} b/{path}\n"
        f"new file mode 100644\n"
        f"--- /dev/null\n"
        f"+++ b/{path}\n"
        f"{hunk}{body}"
    )


def _pr_review_registry_lines(entry, content: str, config) -> frozenset[tuple[str, int]]:
    """Registry (rule_id, line) pairs via parse_config_diff + config handlers (PR path)."""
    targets = [_corpus_managed_target(entry)]
    diff_text = _synthetic_add_file_diff(entry.virtual_path, content)
    fs = config.models.foundation_sec
    parsed = parse_config_diff(
        diff_text,
        max_hunk_lines=fs.max_hunk_lines,
        context_lines_before=fs.context_lines_before,
        context_lines_after=fs.context_lines_after,
    )
    routed = route_changes(
        parsed,
        config.routing,
        repo=_CORPUS_REPO,
        targets=targets,
    ).config_files
    if not routed:
        return frozenset()
    findings = findings_from_config_handlers(
        routed,
        repo=_CORPUS_REPO,
        pr_ref="PR-1",
        commit_sha="eval",
        targets=targets,
        config=config,
    )
    return registry_rule_lines_from_findings(findings)


@pytest.mark.parametrize(
    ("corpus_dir",),
    [
        (GENERATED_CORPUS_DIR,),
        (HOLDOUT_CORPUS_DIR,),
    ],
)
def test_eval_gate_registry_rule_line_parity(corpus_dir: Path) -> None:
    config = _default_eval_config()
    mismatches: list[str] = []

    for entry in load_corpus(corpus_dir):
        if entry.target_type not in _CORPUS_TARGET_TYPES:
            continue
        content = (corpus_dir / entry.rel_path).read_text()
        eval_lines = registry_rule_line_set_for_path(
            entry.target_type,
            entry.virtual_path,
            content,
        )
        gate_findings = findings_for_corpus_file(
            path=entry.virtual_path,
            target_type=entry.target_type,
            content=content,
            config=config,
        )
        gate_lines = registry_rule_lines_from_findings(gate_findings)
        if eval_lines != gate_lines:
            mismatches.append(
                f"{entry.rel_path}\n"
                f"  eval:  {sorted(eval_lines)}\n"
                f"  gate:  {sorted(gate_lines)}"
            )

    assert not mismatches, "registry rule parity mismatches:\n" + "\n".join(mismatches)


@pytest.mark.parametrize(
    ("corpus_dir",),
    [
        (GENERATED_CORPUS_DIR,),
        (HOLDOUT_CORPUS_DIR,),
    ],
)
def test_skip_advisory_matches_normal_gate_findings(corpus_dir: Path) -> None:
    config = _default_eval_config()
    mismatches: list[str] = []

    for entry in load_corpus(corpus_dir):
        if entry.target_type not in _CORPUS_TARGET_TYPES:
            continue
        content = (corpus_dir / entry.rel_path).read_text()
        normal_findings = findings_for_corpus_file(
            path=entry.virtual_path,
            target_type=entry.target_type,
            content=content,
            config=config,
        )
        skip_findings = findings_from_config_handlers(
            [_corpus_changed_file(entry, content)],
            repo=_CORPUS_REPO,
            pr_ref="PR-1",
            commit_sha="eval",
            targets=[_corpus_managed_target(entry)],
            config=config,
        )
        normal_lines = _handler_rule_lines(normal_findings)
        skip_lines = _handler_rule_lines(skip_findings)
        if normal_lines != skip_lines:
            mismatches.append(
                f"{entry.rel_path}\n"
                f"  normal: {sorted(normal_lines)}\n"
                f"  skip:   {sorted(skip_lines)}"
            )

    assert not mismatches, "skip_advisory parity mismatches:\n" + "\n".join(mismatches)


@pytest.mark.parametrize(
    ("corpus_dir",),
    [
        (GENERATED_CORPUS_DIR,),
        (HOLDOUT_CORPUS_DIR,),
    ],
)
def test_eval_gate_path_claim_matches_target_parser_scope(corpus_dir: Path) -> None:
    config = _default_eval_config()
    mismatches: list[str] = []

    for entry in load_corpus(corpus_dir):
        if entry.target_type not in _CORPUS_TARGET_TYPES:
            continue
        target = _corpus_managed_target(entry)
        claim = classify_path(
            entry.virtual_path,
            config.routing,
            repo=_CORPUS_REPO,
            targets=[target],
        )
        in_scope = path_in_target_parser_scope(entry.target_type, entry.virtual_path)
        pr_claimed = claim == PathClaim.CONFIG
        if pr_claimed != in_scope:
            mismatches.append(
                f"{entry.rel_path}: pr_claimed={pr_claimed} parser_scope={in_scope} claim={claim.value}"
            )

    assert not mismatches, "path-claim parity mismatches:\n" + "\n".join(mismatches)


@pytest.mark.parametrize(
    ("corpus_dir",),
    [
        (GENERATED_CORPUS_DIR,),
        (HOLDOUT_CORPUS_DIR,),
    ],
)
def test_eval_gate_pr_unified_diff_rule_line_parity(corpus_dir: Path) -> None:
    """Fourth leg: synthetic add-file unified diff through the PR review handler path.

    Legs 1–3 feed raw file text (or a ChangedHunk whose content is already file
    text). That cannot see extractors that keep ``+/-/ `` prefixes on hunk.content.
    """
    config = _default_eval_config()
    mismatches: list[str] = []

    for entry in load_corpus(corpus_dir):
        if entry.target_type not in _CORPUS_TARGET_TYPES:
            continue
        content = (corpus_dir / entry.rel_path).read_text()
        file_findings = findings_for_corpus_file(
            path=entry.virtual_path,
            target_type=entry.target_type,
            content=content,
            config=config,
        )
        file_lines = registry_rule_lines_from_findings(file_findings)
        pr_lines = _pr_review_registry_lines(entry, content, config)
        if file_lines != pr_lines:
            mismatches.append(
                f"{entry.rel_path}\n"
                f"  file: {sorted(file_lines)}\n"
                f"  pr:   {sorted(pr_lines)}"
            )

    assert not mismatches, (
        f"{len(mismatches)} PR unified-diff parity mismatch(es):\n" + "\n".join(mismatches)
    )
