"""Entry point for IOS-XE parser-backed registry rules."""

from __future__ import annotations

from shift_left.handlers.config.parsers.ios_xe.checks import match_ios_xe_rule
from shift_left.handlers.config.types import ConfigRuleMatch


def match_ios_xe_config_rules(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
    declared_target_type: str = "cisco_ios_xe",
) -> list[ConfigRuleMatch]:
    return match_ios_xe_rule(
        chunk_content=chunk_content,
        line_offset=line_offset,
        rule_id=rule_id,
        declared_target_type=declared_target_type,
    )
