"""Entry point for ASA / FTD parser-backed registry rules."""

from __future__ import annotations

from shift_left.handlers.config.parsers.asa.checks import match_asa_rule
from shift_left.handlers.config.types import ConfigRuleMatch


def match_asa_config_rules(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
) -> list[ConfigRuleMatch]:
    return match_asa_rule(
        chunk_content=chunk_content,
        line_offset=line_offset,
        rule_id=rule_id,
    )
