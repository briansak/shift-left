"""Entry point for FTD FMC parser-backed registry rules."""

from __future__ import annotations

from shift_left.handlers.config.parsers.ftd.checks import match_ftd_rule
from shift_left.handlers.config.types import ConfigRuleMatch


def match_ftd_fmc_rules(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
) -> list[ConfigRuleMatch]:
    return match_ftd_rule(
        chunk_content=chunk_content,
        line_offset=line_offset,
        rule_id=rule_id,
    )
