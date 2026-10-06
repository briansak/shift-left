"""Tests for validation/analyze_model_line_attribution.py."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
if str(VALIDATION) not in sys.path:
    sys.path.insert(0, str(VALIDATION))

from analyze_model_line_attribution import (  # noqa: E402
    analyze_report,
    classify_attribution,
    locate_evidence,
)


def test_locate_evidence_finds_exact_line() -> None:
    content = "line one\nsnmp-server community nms-ro-9c2f RO\nline three\n"
    match = locate_evidence(content, "snmp-server community nms-ro-9c2f RO")
    assert match.line_numbers == (2,)


def test_classify_attribution_mismatch_when_outside_cite_range() -> None:
    category, delta, tight, wide = classify_attribution(
        cited_start=27,
        cited_end=27,
        actual_lines=(15,),
    )
    assert category == "mismatch"
    assert delta == -12
    assert tight is False
    assert wide is False


def test_analyze_report_records_quant_metadata() -> None:
    report_path = ROOT / "validation" / "reports" / "model-vs-handler.json"
    if not report_path.is_file():
        return
    source = json.loads(report_path.read_text(encoding="utf-8"))
    result = analyze_report(source, source_report_path=report_path)
    assert result["source"]["quant_evaluated"] == "Q8_0"
    assert result["source"]["quant_intended"] == "Q4_K_M"
    assert result["summary"]["findings_total"] == len(source["unlabeled_model_findings"])
    assert (
        result["summary"]["contains"]
        + result["summary"]["mismatch"]
        + result["summary"]["fabricated"]
        == result["summary"]["findings_total"]
    )
