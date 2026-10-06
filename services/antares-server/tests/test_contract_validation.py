"""Contract validation tests using captured raw Antares completions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from antares_server.contract import parse_and_validate_findings

ROOT = Path(__file__).resolve().parents[3]
CAPTURES_PATH = ROOT / "validation" / "reports" / "antares-raw-captures.json"


@pytest.fixture(scope="module")
def raw_captures() -> dict:
    if not CAPTURES_PATH.is_file():
        pytest.skip(
            "validation/reports/antares-raw-captures.json is not in the release tree. "
            "Regenerate it locally with: python scripts/capture-antares-raw.py"
        )
    return json.loads(CAPTURES_PATH.read_text())


@pytest.fixture
def catalog(tmp_path: Path) -> frozenset[str]:
    for cwe in ("CWE-89", "CWE-22", "CWE-78", "CWE-284", "CWE-798"):
        (tmp_path / f"{cwe}.json").write_text('{"id": "' + cwe + '"}')
    return frozenset({item.stem for item in tmp_path.glob("CWE-*.json")})


def _capture(raw_captures: dict, name: str) -> dict:
    for item in raw_captures["captures"]:
        if item["fixture"] == name:
            return item
    raise KeyError(name)


def test_sqli_capture_fails_contract(raw_captures, catalog) -> None:
    item = _capture(raw_captures, "sqli_python")
    result = parse_and_validate_findings(
        item["raw_completion_verbatim"],
        default_path=item["file_path"],
        catalog=catalog,
    )
    assert result.ok is False
    assert result.findings == []
    assert "incomplete" in (result.failure_message or "").lower() or "malformed" in (
        result.failure_message or ""
    ).lower()


def test_path_traversal_capture_rejects_fences_and_duplicates(raw_captures, catalog) -> None:
    item = _capture(raw_captures, "path_traversal")
    result = parse_and_validate_findings(
        item["raw_completion_verbatim"],
        default_path=item["file_path"],
        catalog=catalog,
    )
    assert result.ok is False
    assert result.had_markdown_fence is True
    assert any("fence" in v for v in result.violations)
    assert any("trace" in v or "cwe" in v for v in result.violations)


def test_hardcoded_secret_capture_fails_json_contract(raw_captures, catalog) -> None:
    item = _capture(raw_captures, "hardcoded_secret")
    result = parse_and_validate_findings(
        item["raw_completion_verbatim"],
        default_path=item["file_path"],
        catalog=catalog,
    )
    assert result.ok is False
    assert result.findings == []


def test_empty_array_is_valid(catalog) -> None:
    result = parse_and_validate_findings("[]", default_path="app/x.py", catalog=catalog)
    assert result.ok is True
    assert result.findings == []


def test_valid_finding_accepted(catalog) -> None:
    raw = json.dumps(
        [
            {
                "file_path": "app/db.py",
                "line_start": 2,
                "line_end": 3,
                "cwe": "CWE-89",
                "severity": "high",
                "confidence": 0.91,
                "title": "Likely SQL injection",
                "description": "User input concatenated into SQL.",
                "evidence": "f-string query",
                "trace": "diff-hunk",
            }
        ]
    )
    result = parse_and_validate_findings(raw, default_path="app/db.py", catalog=catalog)
    assert result.ok is True
    assert len(result.findings) == 1
    assert result.findings[0]["cwe"] == "CWE-89"


def test_invalid_cwe_rejected(catalog) -> None:
    raw = json.dumps(
        [
            {
                "file_path": "app/db.py",
                "line_start": 2,
                "line_end": 3,
                "cwe": "10",
                "severity": "high",
                "confidence": 0.9,
                "title": "Likely SQL injection",
                "description": "bad cwe",
                "evidence": "x",
                "trace": "y",
            }
        ]
    )
    result = parse_and_validate_findings(raw, default_path="app/db.py", catalog=catalog)
    assert result.ok is False
    assert any("cwe" in v.lower() for v in result.violations)


def test_duplicate_findings_rejected(catalog) -> None:
    raw = json.dumps(
        [
            {
                "file_path": "app/files.py",
                "line_start": 5,
                "line_end": 6,
                "cwe": "CWE-22",
                "severity": "medium",
                "confidence": 0.8,
                "title": "Path issue",
                "description": "desc",
                "evidence": "ev",
                "trace": "tr",
            },
            {
                "file_path": "app/files.py",
                "line_start": 5,
                "line_end": 6,
                "cwe": "CWE-22",
                "severity": "medium",
                "confidence": 0.8,
                "title": "Path issue",
                "description": "desc2",
                "evidence": "ev2",
                "trace": "tr2",
            },
        ]
    )
    result = parse_and_validate_findings(raw, default_path="app/files.py", catalog=catalog)
    assert result.ok is False
    assert any("duplicate" in v for v in result.violations)


def test_analyze_engine_returns_failed_on_contract_violation(raw_captures, catalog, monkeypatch) -> None:
    from antares_server.inference import AntaresEngine

    item = _capture(raw_captures, "path_traversal")
    monkeypatch.setattr(
        "antares_server.contract.load_cwe_catalog",
        lambda: catalog,
    )
    engine = AntaresEngine.__new__(AntaresEngine)
    parsed = engine._parse_findings(item["raw_completion_verbatim"], item["file_path"])
    assert parsed.ok is False
