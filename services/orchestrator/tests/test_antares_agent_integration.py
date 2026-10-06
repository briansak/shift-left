"""Code handler rules and CWE query selection."""

from __future__ import annotations

from shift_left.handlers.code_cwe_rules import (
    findings_from_code_handlers,
    match_code_handler_cwe,
)
from shift_left.diff.extractor import ChangedFile, ChangedHunk


def _changed(path: str, content: str) -> ChangedFile:
    return ChangedFile(
        path=path,
        is_new_file=False,
        is_deleted=False,
        hunks=[
            ChangedHunk(
                file_path=path,
                old_start=1,
                new_start=1,
                new_end=1,
                content=f"+{content}",
                is_new_file=False,
                is_deleted=False,
            )
        ],
    )


def test_match_sqli_pattern() -> None:
    match = match_code_handler_cwe(
        content='cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        path="app/db.py",
    )
    assert match is not None
    assert match.cwe == "CWE-89"


def test_handler_findings_include_handler_asserted_cwe() -> None:
    findings = findings_from_code_handlers(
        [_changed("app/db.py", 'cursor.execute("SELECT 1")')],
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
    )
    assert len(findings) == 1
    assert findings[0].handler_asserted_cwe == "CWE-89"
    assert findings[0].trace.startswith("handler:")


def test_code_findings_include_line_range() -> None:
    findings = findings_from_code_handlers(
        [_changed("app/db.py", 'cursor.execute("SELECT 1")')],
        repo="o/r",
        pr_ref="PR-1",
        commit_sha="abc",
    )
    assert findings[0].line_range is not None
    assert findings[0].source.value == "code-handler"
