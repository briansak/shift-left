"""Shared registry matching re-export — parity with eval harness and PR gate.

Foundation-Sec does not run deterministic Terraform matching at inference time
(the orchestrator gate owns that). This module pins python-hcl2 directly and
exposes the unified registry matcher for tests and tooling.
"""

from __future__ import annotations

import hcl2  # noqa: F401 — direct dependency; gate/eval parity uses the same parser

from shift_left.handlers.config.registry_matching import (
    match_registry_rules,
    registry_rule_line_set_for_path,
)

__all__ = [
    "hcl2",
    "match_registry_rules",
    "registry_rule_line_set_for_path",
]
