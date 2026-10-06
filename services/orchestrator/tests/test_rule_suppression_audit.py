"""Guard against cross-rule suppression in deterministic registry checks."""

from __future__ import annotations

import inspect

from shift_left.handlers.config.parsers.ios_xe.checks import check_ios_001


def test_ios_001_does_not_short_circuit_on_platform_mismatch() -> None:
    source = inspect.getsource(check_ios_001)
    assert "platform_mismatch_line" not in source
