"""match_handler_cwes must invoke every registry parser with required kwargs."""

from __future__ import annotations

import inspect

import pytest

from foundation_sec_server.handlers.cwe_rules import match_handler_cwes
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY
from shift_left.handlers.config.parsers import PARSERS, invoke_parser
from shift_left.handlers.config.rules.registry import (
    ALL_RULES,
    RULE_HANDLER_NAMES,
    rules_for_target_type,
)

_INVOKE_KWARGS = frozenset(
    {"chunk_content", "line_offset", "rule_id", "declared_target_type"}
)

_SAMPLE_BY_TARGET_TYPE = {
    "cisco_secure_firewall": "access-list OUTSIDE extended permit ip any any\n",
    "cisco_ios_xe": "ip access-list extended EDGE\n permit ip any any\n",
    "cisco_nx_os": "ip access-list EDGE\n 10 permit ip any any\n",
    "cisco_ftd": 'resource "fmc_access_rules" "open" {\n  action = "ALLOW"\n}\n',
    "generic_terraform": (
        'resource "aws_security_group_rule" "open" {\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n'
        "}\n"
    ),
}

ENABLED_TARGET_TYPES = sorted(
    {rule.target_type for rule in ALL_RULES if rule.enabled}
)


def _handlers_for_target_type(target_type: str):
    names: set[str] = set()
    for rule in rules_for_target_type(target_type):
        names.update(RULE_HANDLER_NAMES.get(rule.id, frozenset()))
    handlers = [handler for handler in DEFAULT_REGISTRY._handlers if handler.name in names]
    assert handlers, f"no ConfigFormatHandler mapped for target_type={target_type}"
    return handlers


def test_every_parser_required_argument_is_known_to_invoke_parser() -> None:
    for name, parser in PARSERS.items():
        for key, param in inspect.signature(parser).parameters.items():
            if param.kind in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            ):
                continue
            if param.default is not inspect.Parameter.empty:
                continue
            assert key in _INVOKE_KWARGS, (
                f"parser {name!r} requires {key!r}, which invoke_parser cannot supply"
            )


def test_invoke_parser_supplies_nx_os_rule_id() -> None:
    matches = invoke_parser(
        "nx_os_config",
        chunk_content="ip access-list EDGE\n 10 permit ip any any\n",
        rule_id="NXOS-001",
    )
    assert isinstance(matches, list)


@pytest.mark.parametrize("target_type", ENABLED_TARGET_TYPES)
def test_match_handler_cwes_every_target_type(target_type: str) -> None:
    sample = _SAMPLE_BY_TARGET_TYPE.get(target_type)
    assert sample is not None, f"add a sample snippet for target_type={target_type}"
    for handler in _handlers_for_target_type(target_type):
        matches = match_handler_cwes(chunk_content=sample, handler=handler)
        assert isinstance(matches, list)
