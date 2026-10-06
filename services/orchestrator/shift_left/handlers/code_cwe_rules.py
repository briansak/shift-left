"""Deterministic code-path handler findings — PR gate signal only."""

from __future__ import annotations

import re
from dataclasses import dataclass

from shift_left.diff.extractor import ChangedFile, ChangedHunk
from shift_left.handlers.code.registry import rules_for_path, validate_code_rules
from shift_left.models.schema import Finding, FindingSource, LineRange, Severity, TargetKind
from shift_left.policy import construct_key as construct

validate_code_rules()


@dataclass(frozen=True)
class CodeHandlerCweMatch:
    cwe: str
    pattern_id: str
    title: str


def match_code_handler_cwe(*, content: str, path: str) -> CodeHandlerCweMatch | None:
    matches = match_code_handler_rules(content=content, path=path)
    if not matches:
        return None
    rule, _ = matches[0]
    return CodeHandlerCweMatch(cwe=rule.handler_asserted_cwe, pattern_id=rule.id, title=rule.title)


def _line_range_for_match(hunk: ChangedHunk, content: str, match: re.Match[str]) -> LineRange:
    prefix = content[: match.start()]
    line_offset = prefix.count("\n")
    start = hunk.new_start + line_offset
    end = start + match.group(0).count("\n")
    return LineRange(start=start, end=max(start, end))


def match_code_handler_rules(*, content: str, path: str) -> list[tuple[object, re.Match[str]]]:
    matches: list[tuple[object, re.Match[str]]] = []
    for rule in rules_for_path(path):
        if rule.path_predicate and not rule.path_predicate(path):
            continue
        found = rule.pattern.search(content)
        if found:
            matches.append((rule, found))
    return matches


def findings_from_code_handlers(
    files: list[ChangedFile],
    *,
    repo: str,
    pr_ref: str,
    commit_sha: str,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    for changed in files:
        for hunk in changed.hunks:
            for rule, match in match_code_handler_rules(content=hunk.content, path=changed.path):
                line_range = _line_range_for_match(hunk, hunk.content, match)
                key_construct = construct.snippet(match.group(0))
                key = (changed.path, rule.id, key_construct)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        source=FindingSource.CODE_HANDLER,
                        target_kind=TargetKind.CODE,
                        repo=repo,
                        pr_ref=pr_ref,
                        commit_sha=commit_sha,
                        file_path=changed.path,
                        line_range=line_range,
                        handler_asserted_cwe=rule.handler_asserted_cwe,
                        model_asserted_severity=Severity.MEDIUM,
                        confidence=0.55,
                        title=rule.title,
                        description=rule.description,
                        trace=f"handler:{rule.id}",
                        construct_key=key_construct,
                    )
                )
    return findings
