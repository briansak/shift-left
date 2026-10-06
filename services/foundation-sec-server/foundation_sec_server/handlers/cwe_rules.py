"""Deterministic handler CWE assertions — independent of model output."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from shift_left.handlers.config.parsers import invoke_parser
from shift_left.handlers.config.parsers.ios_xe.platform import SniffedPlatform, sniff_platform
from shift_left.handlers.config.registry_matching import undetermined_platform_matches
from shift_left.handlers.config.rules.registry import (
    UNDETERMINED_PLATFORM_RULE_ID,
    rule_by_id,
    rules_for_handler,
)
from shift_left.handlers.config.types import ConfigRuleMatch

from foundation_sec_server.findings_policy import MODEL_SERVER_HANDLER_ASSERTED_CWE
from foundation_sec_server.handlers.registry import ConfigFormatHandler
from foundation_sec_server.handlers.types import HandlerCweMatch

EvaluationStatus = Literal["matched", "unevaluated"]


@dataclass(frozen=True)
class HandlerCweRule:
    id: str
    handler_names: frozenset[str]
    cwe: str
    precision_intent: str
    matcher: re.Pattern[str] | None = None
    predicate: str | None = None


def _matches_wildcard_sudo(text: str) -> bool:
    return bool(
        re.search(r"ALL\s+ALL=\(ALL\)\s+NOPASSWD:\s*ALL", text, re.IGNORECASE)
        or re.search(r"NOPASSWD:\s*ALL", text, re.IGNORECASE)
    )


def _matches_hostnetwork(text: str) -> bool:
    return bool(re.search(r"^\s*hostNetwork:\s*true\s*$", text, re.MULTILINE | re.IGNORECASE))


def _matches_missing_tls(text: str) -> bool:
    if re.search(r"listen\s+\d+\s+ssl", text, re.IGNORECASE):
        return False
    if re.search(r"ssl_certificate", text, re.IGNORECASE):
        return False
    return bool(re.search(r"listen\s+80\s*;", text, re.IGNORECASE))


CONFIG_HANDLER_RULES: tuple[HandlerCweRule, ...] = (
    HandlerCweRule(
        id="kubernetes/hostnetwork",
        handler_names=frozenset({"kubernetes"}),
        cwe="CWE-250",
        precision_intent="High — hostNetwork: true on Pod/Deployment spec.",
        predicate="hostnetwork",
    ),
    HandlerCweRule(
        id="ansible/wildcard-sudo",
        handler_names=frozenset({"ansible"}),
        cwe="CWE-269",
        precision_intent="High — NOPASSWD ALL / ALL ALL=(ALL) NOPASSWD: ALL.",
        predicate="wildcard_sudo",
    ),
    HandlerCweRule(
        id="nginx/plaintext-listener",
        handler_names=frozenset({"nginx"}),
        cwe="CWE-319",
        precision_intent="High — listen 80 without ssl on server block.",
        predicate="missing_tls",
    ),
)


def _to_handler_match(match: ConfigRuleMatch) -> HandlerCweMatch:
    return HandlerCweMatch(
        cwe=match.cwe,
        pattern_id=match.pattern_id,
        line_start=match.line_start,
        line_end=match.line_end,
        evaluation_status=match.evaluation_status,
        title=match.title,
        description=match.description,
    )


# CLI families the platform sniffer can tell apart. An undeclared device/generic
# chunk must not run another family's parser: those parsers default
# declared_target_type to their own platform and then report ASA syntax as an
# unparsed IOS-XE or NX-OS ACL (IOS-001 / NXOS-001) plus a mismatch (IOS-010 /
# NXOS-002). A declared target still goes through match_registry_rules, which
# keeps IOS-001 when the operator declared cisco_ios_xe and the body is ASA.
_CLI_PLATFORM_TARGET_TYPES = frozenset(
    {
        "cisco_ios_xe",
        "cisco_nx_os",
        "cisco_secure_firewall",
    }
)


def _sniffed_cli_target(content: str) -> str | None:
    sniffed = sniff_platform(content)
    if sniffed == SniffedPlatform.UNKNOWN:
        return None
    return sniffed.value


def _undetermined_platform_constants() -> tuple[str, str]:
    rule = rule_by_id(UNDETERMINED_PLATFORM_RULE_ID)
    if rule is None:
        return "CWE-754", "block"
    return rule.cwe, rule.severity


UNDETERMINED_PLATFORM_CWE, UNDETERMINED_PLATFORM_SEVERITY = _undetermined_platform_constants()


def _undetermined_platform_match(content: str, line_offset: int) -> HandlerCweMatch:
    match = undetermined_platform_matches(content)[0]
    return HandlerCweMatch(
        cwe=match.cwe,
        pattern_id=match.pattern_id,
        line_start=(match.line_start or 1) + line_offset,
        line_end=(match.line_end or 1) + line_offset,
        evaluation_status="matched",
        title=match.title,
        description=match.description,
    )


def _registry_rule_matches(
    *,
    chunk_content: str,
    handler: ConfigFormatHandler,
    line_offset: int,
) -> list[HandlerCweMatch]:
    # Terraform deterministic rules are owned by the orchestrator gate only.
    if handler.name == "terraform":
        return []
    rules = rules_for_handler(handler.name)
    cli_rules = [rule for rule in rules if rule.target_type in _CLI_PLATFORM_TARGET_TYPES]
    sniffed_target = _sniffed_cli_target(chunk_content) if cli_rules else None
    # Unknown sniff: do not guess a platform and do not run every CLI family.
    if cli_rules and sniffed_target is None:
        if not chunk_content.strip():
            return []
        return [_undetermined_platform_match(chunk_content, line_offset)]
    matches: list[HandlerCweMatch] = []
    for rule in rules:
        if (
            sniffed_target is not None
            and rule.target_type in _CLI_PLATFORM_TARGET_TYPES
            and rule.target_type != sniffed_target
        ):
            continue
        raw_matches = invoke_parser(
            rule.parser,
            chunk_content=chunk_content,
            line_offset=line_offset,
            rule_id=rule.id,
        )
        matches.extend(_to_handler_match(item) for item in raw_matches)
    return matches


def _rule_matches(rule: HandlerCweRule, *, chunk_content: str, handler: ConfigFormatHandler) -> bool:
    if handler.name not in rule.handler_names:
        return False
    if rule.predicate == "hostnetwork":
        return _matches_hostnetwork(chunk_content)
    if rule.predicate == "wildcard_sudo":
        return _matches_wildcard_sudo(chunk_content)
    if rule.predicate == "missing_tls":
        return _matches_missing_tls(chunk_content)
    if rule.matcher is not None:
        return bool(rule.matcher.search(chunk_content))
    return False


def _legacy_rule_match(
    *,
    chunk_content: str,
    handler: ConfigFormatHandler,
    line_offset: int,
) -> list[HandlerCweMatch]:
    matches: list[HandlerCweMatch] = []
    for rule in CONFIG_HANDLER_RULES:
        if _rule_matches(rule, chunk_content=chunk_content, handler=handler):
            matches.append(
                HandlerCweMatch(
                    cwe=rule.cwe,
                    pattern_id=rule.id,
                    evaluation_status="matched",
                    title=f"Deterministic rule: {rule.id}",
                    description=rule.precision_intent,
                    line_start=1 + line_offset,
                    line_end=max(1, len(chunk_content.splitlines())) + line_offset,
                )
            )
    return matches


def match_handler_cwes(
    *,
    chunk_content: str,
    handler: ConfigFormatHandler,
    line_offset: int = 0,
) -> list[HandlerCweMatch]:
    """Return advisory handler rule matches for a chunk (no gate CWE influence)."""
    registry_matches = _registry_rule_matches(
        chunk_content=chunk_content,
        handler=handler,
        line_offset=line_offset,
    )
    legacy_matches = _legacy_rule_match(
        chunk_content=chunk_content,
        handler=handler,
        line_offset=line_offset,
    )
    return registry_matches + legacy_matches


def match_handler_cwe(*, chunk_content: str, handler: ConfigFormatHandler) -> HandlerCweMatch | None:
    """Return the first matched handler-asserted CWE (not unevaluated)."""
    for match in match_handler_cwes(chunk_content=chunk_content, handler=handler):
        if match.evaluation_status == "matched" and match.cwe:
            return match
    return None


def attach_handler_cwe(finding: dict, match: HandlerCweMatch | None) -> None:
    if match is None:
        return
    # Trace-only correlation — model-server findings must not set handler_asserted_cwe.
    finding["handler_asserted_cwe"] = MODEL_SERVER_HANDLER_ASSERTED_CWE
    trace = (finding.get("trace") or "").strip()
    marker = f"handler:{match.pattern_id}"
    if match.evaluation_status == "unevaluated":
        marker = f"handler:unevaluated/{match.pattern_id}"
    if marker not in trace:
        finding["trace"] = f"{marker} | {trace}".strip(" |")
    if match.line_start is not None and match.line_end is not None:
        finding.setdefault("line_start", match.line_start)
        finding.setdefault("line_end", match.line_end)
