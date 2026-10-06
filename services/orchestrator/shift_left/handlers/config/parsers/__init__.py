"""Config handler parsers — referenced by name from the rule registry."""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from shift_left.handlers.config.parsers.asa_config import match_asa_config_rules
from shift_left.handlers.config.parsers.ftd_fmc import match_ftd_fmc_rules
from shift_left.handlers.config.parsers.ios_xe_config import match_ios_xe_config_rules
from shift_left.handlers.config.parsers.nx_os_config import match_nx_os_config_rules
from shift_left.handlers.config.parsers.terraform_hcl import match_terraform_hcl_rules
from shift_left.handlers.config.types import ConfigRuleMatch

ParserFn = Callable[..., list[ConfigRuleMatch]]


def match_hcl_provider_coverage_rules(**_kwargs: object) -> list[ConfigRuleMatch]:
    """No-op: uncovered-provider matches are injected in registry_matching."""
    return []


PARSERS: dict[str, ParserFn] = {
    "asa_config": match_asa_config_rules,
    "ios_xe_config": match_ios_xe_config_rules,
    "nx_os_config": match_nx_os_config_rules,
    "ftd_fmc": match_ftd_fmc_rules,
    "hcl_provider_coverage": match_hcl_provider_coverage_rules,
    "terraform_hcl": match_terraform_hcl_rules,
}


def get_parser(name: str) -> ParserFn:
    try:
        return PARSERS[name]
    except KeyError as exc:
        raise KeyError(f"unknown config handler parser: {name}") from exc


def invoke_parser(
    name: str,
    *,
    chunk_content: str,
    line_offset: int = 0,
    rule_id: str | None = None,
    declared_target_type: str | None = None,
) -> list[ConfigRuleMatch]:
    """Call a registry parser with only the kwargs its signature accepts."""
    parser = get_parser(name)
    params = inspect.signature(parser).parameters
    accepts_var_keyword = any(
        item.kind is inspect.Parameter.VAR_KEYWORD for item in params.values()
    )
    provided: dict[str, Any] = {
        "chunk_content": chunk_content,
        "line_offset": line_offset,
    }
    if rule_id is not None:
        provided["rule_id"] = rule_id
    if declared_target_type is not None:
        provided["declared_target_type"] = declared_target_type

    kwargs: dict[str, Any] = {}
    for key, param in params.items():
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if key in provided:
            kwargs[key] = provided[key]
            continue
        if param.default is inspect.Parameter.empty:
            raise TypeError(f"{name}() missing required keyword-only argument: {key!r}")
    if accepts_var_keyword:
        for key, value in provided.items():
            kwargs.setdefault(key, value)
    return parser(**kwargs)
