"""Tests for shared eval metadata stamping."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VALIDATION = ROOT / "validation"
if str(VALIDATION) not in sys.path:
    sys.path.insert(0, str(VALIDATION))

from report_quant_stamping import (  # noqa: E402
    CHAT_TEMPLATE_FIDELITY_SUMMARY,
    STRUCTURED_OUTPUT_CAVEAT_SUMMARY,
    chat_template_fidelity_fields,
    merge_quant_metadata,
    structured_output_caveat_fields,
)


def test_chat_template_fidelity_fields_use_canonical_summary() -> None:
    fields = chat_template_fidelity_fields()
    assert fields["chat_template_fidelity_summary"] == CHAT_TEMPLATE_FIDELITY_SUMMARY
    assert fields["inference_path"] == "raw_completion"
    assert "raw completion (authoritative)" in fields["chat_template_fidelity_summary"]
    assert fields["uses_model_specific_jinja_template"] is False


def test_merge_quant_metadata_includes_fidelity() -> None:
    merged = merge_quant_metadata({"experiment": "test"})
    assert merged["chat_template_fidelity_summary"] == CHAT_TEMPLATE_FIDELITY_SUMMARY
    assert merged["quant_evaluated"] == "Q8_0"


def test_structured_output_caveat_fields_present() -> None:
    fields = structured_output_caveat_fields()
    assert fields["structured_output_caveat_summary"] == STRUCTURED_OUTPUT_CAVEAT_SUMMARY
    assert "13/108" in fields["structured_output_caveat_summary"]
    assert fields["methodology_artifact_count"] == 5


def test_merge_quant_metadata_includes_structured_output_caveat() -> None:
    merged = merge_quant_metadata({"experiment": "test"})
    assert merged["structured_output_caveat_summary"] == STRUCTURED_OUTPUT_CAVEAT_SUMMARY
    assert merged["methodology_artifact_count"] == 5
