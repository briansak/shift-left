"""Build CTIBench-RCM-shaped CWE assignment inputs from handler match signals."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from eval_handlers import HOLDOUT_CORPUS_DIR, GENERATED_CORPUS_DIR, CorpusEntry, load_corpus
from shift_left.handlers.config.registry_matching import RegistryRuleMatch, match_registry_rules
from shift_left.handlers.config.rules.registry import ALL_RULES, Rule

ROOT = Path(__file__).resolve().parents[1]

_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_RULE_BY_ID: dict[str, Rule] = {rule.id: rule for rule in ALL_RULES}

def normalize_block_text(text: str) -> str:
    """Collapse embedded newlines so defect context stays single-line."""
    collapsed = re.sub(r"\s*\n\s*", "; ", (text or "").strip())
    return re.sub(r"; +", "; ", collapsed)


RCM_PROMPT_TEMPLATE = """You are a cybersecurity expert specializing in cyber threat intelligence.
Analyze the following network configuration defect signal and map it to the appropriate CWE.
Provide a brief justification for your choice.
Ensure the last line of your response contains only the CWE ID.

Configuration block:
```
{config_block}
```

Resolved values:
{resolved_values}

Handler match summary:
{match_description}
"""

ZERO_SHOT_MAX_TOKENS = 512
ZERO_SHOT_COMPLETION_STOP = [
    "\n\nConfiguration block:",
    "\nYou are a cybersecurity expert specializing in cyber threat intelligence.",
]


@dataclass(frozen=True)
class RcmInstance:
    instance_id: str
    corpus: str
    rel_path: str
    target_type: str
    rule_id: str
    expected_cwe: str
    config_block: str
    resolved_values: str
    match_description: str
    prompt: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def corpus_dirs() -> list[tuple[str, Path]]:
    return [
        ("generated", GENERATED_CORPUS_DIR),
        ("holdout", HOLDOUT_CORPUS_DIR),
    ]


def neutral_match_description(rule: Rule, match: RegistryRuleMatch) -> str:
    text = (match.description or match.title or rule.description or rule.id).strip()
    text = _CWE_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip(" -:;")
    return text or f"Deterministic handler matched rule {rule.id}."


def extract_config_block(content: str, line_start: int, line_end: int) -> str:
    lines = content.splitlines()
    start = max(0, line_start - 1)
    end = min(len(lines), line_end)
    if start >= end:
        return ""
    return "\n".join(lines[start:end])


def _format_network_resolution_ftd(resolution: Any) -> list[str]:
    lines: list[str] = []
    if resolution.failure is not None:
        lines.append(f"  failure: {resolution.failure.value}")
    if resolution.values:
        lines.append(f"  values: {', '.join(resolution.values)}")
    lines.append(f"  is_any: {resolution.is_any}")
    if hasattr(resolution, "is_exposed"):
        lines.append(f"  is_exposed: {resolution.is_exposed}")
    if hasattr(resolution, "has_no_constraint"):
        lines.append(f"  has_no_constraint: {resolution.has_no_constraint}")
    return lines


def _resolved_values_ftd(content: str, match: RegistryRuleMatch) -> str:
    from shift_left.handlers.config.parsers.ftd.parser import parse_ftd_fmc_config
    from shift_left.handlers.config.parsers.ftd.resolver import rule_key

    parsed = parse_ftd_fmc_config(content)
    rule = _find_ftd_rule(parsed, match.line_start, match.line_end)
    if rule is None:
        return "(no FMC access rule resolved for matched lines)"

    lines = [
        f"rule_name: {rule.name}",
        f"action: {rule.action}",
        f"source_network_refs: {', '.join(rule.source_networks) or '(none)'}",
        f"destination_network_refs: {', '.join(rule.destination_networks) or '(none)'}",
        f"destination_ports: {', '.join(rule.destination_ports) or '(none)'}",
    ]
    resolution = parsed.rule_resolutions.get(rule_key(rule))
    if resolution is None:
        lines.append("resolution: (unavailable)")
        return "\n".join(lines)

    lines.append("source_resolution:")
    lines.extend(_format_network_resolution_ftd(resolution.source))
    lines.append("destination_resolution:")
    lines.extend(_format_network_resolution_ftd(resolution.destination))
    return "\n".join(lines)


def _find_ftd_rule(parsed: Any, line_start: int, line_end: int) -> Any | None:
    candidates: list[Any] = []
    for rule in parsed.access_rules:
        if rule.line_start <= line_end and rule.line_end >= line_start:
            candidates.append(rule)
    for bulk in parsed.access_rules_bulk:
        for rule in bulk.rules:
            if rule.line_start <= line_end and rule.line_end >= line_start:
                candidates.append(rule)
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item.line_start, item.line_end))


def _resolved_values_asa(content: str, match: RegistryRuleMatch) -> str:
    from shift_left.handlers.config.parsers.asa.parser import parse_asa_config

    parsed = parse_asa_config(content)
    ace = parsed.ace_resolutions.get(match.line_start)
    if ace is None:
        return "(no ACE resolution for matched line)"

    lines = [
        f"ace_line: {match.line_start}",
        "source:",
        f"  is_any: {ace.source.is_any}",
        f"  is_narrow: {ace.source.is_narrow}",
        "destination:",
        f"  is_any: {ace.destination.is_any}",
        f"  is_narrow: {ace.destination.is_narrow}",
    ]
    if ace.service is not None:
        lines.extend(
            [
                "service:",
                f"  is_permissive: {ace.service.is_permissive}",
            ]
        )
    if ace.source.failure is not None:
        lines.append(f"source_failure: {ace.source.failure.value}")
    if ace.destination.failure is not None:
        lines.append(f"destination_failure: {ace.destination.failure.value}")
    return "\n".join(lines)


def _resolved_values_ios_xe(content: str, match: RegistryRuleMatch) -> str:
    from shift_left.handlers.config.parsers.ios_xe.parser import parse_ios_xe_config

    parsed = parse_ios_xe_config(content)
    ace = parsed.ace_resolutions.get(match.line_start)
    if ace is None:
        return "(no IOS-XE ACE resolution for matched line)"

    lines = [
        f"acl: {ace.acl_name}",
        f"ace_line: {ace.line_no}",
        f"source_values: {', '.join(ace.source_values) or '(none)'}",
        f"destination_values: {', '.join(ace.destination_values) or '(none)'}",
        f"service_values: {', '.join(ace.service_values) or '(none)'}",
    ]
    if ace.unresolved:
        unresolved = "; ".join(
            f"{item.ref_kind}:{item.ref_name} ({item.raw})" for item in ace.unresolved
        )
        lines.append(f"unresolved_refs: {unresolved}")
    return "\n".join(lines)


def _resolved_values_generic(content: str, target_type: str, match: RegistryRuleMatch) -> str:
    if target_type == "cisco_ftd":
        return _resolved_values_ftd(content, match)
    from shift_left.handlers.config.hcl_parse import parse_hcl_content

    status = parse_hcl_content(content)
    if status.parsed is None:
        reason = status.error or "HCL not interpretable"
        return f"(HCL parse status: {reason})"
    return f"(parsed_resource_blocks: {status.resource_block_count})"


def resolved_values_for_match(
    *,
    target_type: str,
    content: str,
    match: RegistryRuleMatch,
) -> str:
    if target_type == "cisco_secure_firewall":
        return _resolved_values_asa(content, match)
    if target_type == "cisco_ios_xe":
        return _resolved_values_ios_xe(content, match)
    if target_type in {"cisco_ftd", "generic_terraform"}:
        return _resolved_values_generic(content, target_type, match)
    return "(resolution not available for target type)"


def _select_match(matches: list[RegistryRuleMatch], rule_id: str) -> RegistryRuleMatch:
    rule_matches = [match for match in matches if match.rule_id == rule_id]
    if not rule_matches:
        raise ValueError(f"handler did not match expected rule {rule_id}")
    return min(rule_matches, key=lambda item: (item.line_start, item.line_end))


def build_rcm_prompt(
    *,
    config_block: str,
    resolved_values: str,
    match_description: str,
) -> str:
    return RCM_PROMPT_TEMPLATE.format(
        config_block=normalize_block_text(config_block),
        resolved_values=normalize_block_text(resolved_values) or "(none)",
        match_description=normalize_block_text(match_description),
    )


def build_instance(
    *,
    corpus: str,
    entry: CorpusEntry,
    rule_id: str,
    content: str,
    match: RegistryRuleMatch,
) -> RcmInstance:
    rule = _RULE_BY_ID[rule_id]
    config_block = extract_config_block(content, match.line_start, match.line_end)
    resolved_values = resolved_values_for_match(
        target_type=entry.target_type,
        content=content,
        match=match,
    )
    match_description = neutral_match_description(rule, match)
    prompt = build_rcm_prompt(
        config_block=config_block,
        resolved_values=resolved_values,
        match_description=match_description,
    )
    if rule.cwe.lower() in prompt.lower():
        raise ValueError(f"prompt leaks expected CWE for {corpus}/{entry.rel_path}#{rule_id}")

    return RcmInstance(
        instance_id=f"{corpus}/{entry.rel_path}#{rule_id}",
        corpus=corpus,
        rel_path=entry.rel_path,
        target_type=entry.target_type,
        rule_id=rule_id,
        expected_cwe=rule.cwe,
        config_block=config_block,
        resolved_values=resolved_values,
        match_description=match_description,
        prompt=prompt,
    )


def build_rcm_instances() -> list[RcmInstance]:
    instances: list[RcmInstance] = []
    for corpus_name, corpus_dir in corpus_dirs():
        for entry in load_corpus(corpus_dir):
            if not entry.expected_rule_ids:
                continue
            content = (corpus_dir / entry.rel_path).read_text(encoding="utf-8")
            matches = match_registry_rules(entry.target_type, content)
            for rule_id in sorted(entry.expected_rule_ids):
                match = _select_match(matches, rule_id)
                instances.append(
                    build_instance(
                        corpus=corpus_name,
                        entry=entry,
                        rule_id=rule_id,
                        content=content,
                        match=match,
                    )
                )
    return instances
