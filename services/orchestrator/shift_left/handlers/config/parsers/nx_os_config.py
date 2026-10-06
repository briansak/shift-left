"""Entry point for NX-OS parser-backed registry rules."""

from __future__ import annotations

from shift_left.handlers.config.parsers.nx_os.checks import match_nx_os_rule
from shift_left.handlers.config.types import ConfigRuleMatch


def match_nx_os_config_rules(
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str,
    declared_target_type: str = "cisco_nx_os",
) -> list[ConfigRuleMatch]:
    return match_nx_os_rule(
        chunk_content=chunk_content,
        line_offset=line_offset,
        rule_id=rule_id,
        declared_target_type=declared_target_type,
    )
