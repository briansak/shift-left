"""Tests for advisory JSON array parsing."""

from __future__ import annotations

from foundation_sec_server.engine import _parse_json_findings


def test_parse_json_findings_prepends_array_bracket_for_platform_suffix():
    completion = '{\n  "file_path": "x.tf",\n  "line_start": 1,\n  "line_end": 1,\n  "cwe": "CWE-284"\n}]'
    findings = _parse_json_findings(
        completion,
        "x.tf",
        prepend_array_bracket=True,
    )
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-284"


def test_parse_json_findings_does_not_double_bracket_when_model_repeats():
    completion = '[{"file_path": "x.tf", "line_start": 1, "line_end": 1, "cwe": "CWE-20"}]'
    findings = _parse_json_findings(
        completion,
        "x.tf",
        prepend_array_bracket=True,
    )
    assert len(findings) == 1
