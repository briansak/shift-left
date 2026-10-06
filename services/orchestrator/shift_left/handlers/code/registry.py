"""Pluggable deterministic code handler rules — parallel to config handlers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from shift_left.handlers.cwe_catalog import assert_cwe_in_catalog


@dataclass(frozen=True)
class CodeHandlerRule:
    id: str
    language: str
    path_globs: tuple[str, ...]
    handler_asserted_cwe: str
    title: str
    description: str
    precision_intent: str
    pattern: re.Pattern[str]
    path_predicate: Callable[[str], bool] | None = None


def _python_db_path(path: str) -> bool:
    lowered = path.lower()
    return any(token in lowered for token in ("db", "sql", "query", "repo"))


PYTHON_RULES: tuple[CodeHandlerRule, ...] = (
    CodeHandlerRule(
        id="python/sqli-dynamic-query",
        language="python",
        path_globs=("**/*.py",),
        handler_asserted_cwe="CWE-89",
        title="Dynamic SQL construction in changed Python code",
        description="Deterministic pattern matched dynamic SQL in a changed hunk.",
        precision_intent="High — requires execute/cursor or string-built SELECT in db-ish paths.",
        pattern=re.compile(
            r"(execute\s*\(|cursor\.execute|SELECT\s+.+\+|f[\"']SELECT|format\s*\(\s*[\"']SELECT)",
            re.IGNORECASE,
        ),
        path_predicate=_python_db_path,
    ),
    CodeHandlerRule(
        id="python/hardcoded-secret",
        language="python",
        path_globs=("**/*.py",),
        handler_asserted_cwe="CWE-798",
        title="Possible hard-coded credential in changed Python code",
        description="Deterministic pattern matched credential-like assignment.",
        precision_intent="High — literal secret/password/api_key assignment.",
        pattern=re.compile(
            r"(password|api_key|secret|token)\s*=\s*[\"'][^\"']{4,}[\"']",
            re.IGNORECASE,
        ),
    ),
    CodeHandlerRule(
        id="python/path-traversal",
        language="python",
        path_globs=("**/*.py",),
        handler_asserted_cwe="CWE-22",
        title="Possible path traversal in changed Python code",
        description="Deterministic pattern matched traversal-like path handling.",
        precision_intent="Medium-high — ../ or user-controlled join patterns.",
        pattern=re.compile(
            r"(\.\./|Path\s*\(\s*[^)]*\+|os\.path\.join\s*\(\s*[^,]+,\s*user)",
            re.IGNORECASE,
        ),
    ),
    CodeHandlerRule(
        id="python/os-command-injection",
        language="python",
        path_globs=("**/*.py",),
        handler_asserted_cwe="CWE-78",
        title="Possible OS command injection in changed Python code",
        description="Deterministic pattern matched shell execution with user influence.",
        precision_intent="High — os.system/subprocess shell=True/eval.",
        pattern=re.compile(
            r"(os\.system\s*\(|subprocess\.(run|call|Popen)[^\n]*shell\s*=\s*True|eval\s*\()",
            re.IGNORECASE,
        ),
    ),
)

ALL_CODE_RULES: tuple[CodeHandlerRule, ...] = PYTHON_RULES


def validate_code_rules(rules: tuple[CodeHandlerRule, ...] = ALL_CODE_RULES) -> None:
    for rule in rules:
        assert_cwe_in_catalog(rule.handler_asserted_cwe, rule_id=rule.id)


def rules_for_path(path: str) -> list[CodeHandlerRule]:
    from shift_left.routing.globmatch import matches_any

    matched = [rule for rule in ALL_CODE_RULES if matches_any(path, list(rule.path_globs))]
    return matched
