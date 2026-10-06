"""Quant stamping validation for validation/eval_model.py reports."""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
for path in (ROOT, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from validation.eval_model import (  # noqa: E402
    QUANT_INTENDED,
    ReportWriteError,
    apply_quant_stamping,
    validate_report_writable,
)


def _base_report(*, quant_match: bool, include_timing: bool = False) -> dict:
    gguf = (
        "foundation-sec-1.1-8b-instruct-q4_k_m.gguf"
        if quant_match
        else "foundation-sec-1.1-8b-instruct-q8_0.gguf"
    )
    server_health = {
        "gguf_file": gguf,
        "quant_match": quant_match,
        "inference_verified": True,
    }
    report = {
        "status": "complete",
        "model_config": {
            "required_quant": QUANT_INTENDED,
            "server_health": server_health,
        },
        "summary": {"files_scored_successfully": 1},
    }
    if include_timing:
        report["timing"] = {"total_wall_clock_ms": 1000}
    return report


def test_apply_quant_stamping_sets_model_config_fields_from_server_health() -> None:
    report = _base_report(quant_match=False)
    stamped = apply_quant_stamping(report)

    assert stamped["quant_evaluated"] == "Q8_0"
    assert stamped["quant_intended"] == QUANT_INTENDED
    assert stamped["accuracy_only"] is True

    mc = stamped["model_config"]
    assert mc["quant_evaluated"] == "Q8_0"
    assert mc["quant_intended"] == QUANT_INTENDED
    assert mc["accuracy_only"] is True
    assert mc["quant_match"] is False
    assert mc["server_health"]["quant_evaluated"] == "Q8_0"


def test_validate_report_writable_rejects_null_stamping_when_quant_mismatch() -> None:
    report = _base_report(quant_match=False)
    report["model_config"]["quant_evaluated"] = None
    report["model_config"]["quant_intended"] = None
    report["model_config"]["accuracy_only"] = None

    with pytest.raises(ReportWriteError, match="quant_evaluated"):
        validate_report_writable(report)


def test_validate_report_writable_requires_accuracy_only_and_no_timing_on_mismatch() -> None:
    stamped = apply_quant_stamping(_base_report(quant_match=False))
    validate_report_writable(stamped)

    bad_accuracy = copy.deepcopy(stamped)
    bad_accuracy["accuracy_only"] = False
    with pytest.raises(ReportWriteError, match="accuracy_only must be true"):
        validate_report_writable(bad_accuracy)

    with_timing = copy.deepcopy(stamped)
    with_timing["timing"] = {"total_wall_clock_ms": 1}
    with pytest.raises(ReportWriteError, match="timing must be absent"):
        validate_report_writable(with_timing)


def test_validate_report_writable_allows_matched_quant_with_timing() -> None:
    report = apply_quant_stamping(_base_report(quant_match=True, include_timing=True))
    validate_report_writable(report)
    assert report["accuracy_only"] is False
    assert "timing" in report
