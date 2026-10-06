"""Presentation redaction helpers for investigation trace text."""

from __future__ import annotations

from shift_left.investigations.schema import TraceRecord
from shift_left.ui.config_redaction import redact_display_text


def redact_trace_record_for_display(record: TraceRecord) -> TraceRecord:
    """Apply the presentation chokepoint to a persisted trace turn."""
    return record.model_copy(
        update={
            "command": redact_display_text(record.command),
            "output_truncated": redact_display_text(record.output_truncated),
        }
    )
