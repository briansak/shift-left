"""Build Experiment G inputs: contextual remediation from handler defect signals."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from eval_handlers import HOLDOUT_CORPUS_DIR, GENERATED_CORPUS_DIR, CorpusEntry, load_corpus
from rcm_cwe_inputs import (
    _RULE_BY_ID,
    _select_match,
    corpus_dirs,
    extract_config_block,
    resolved_values_for_match,
)
from shift_left.handlers.config.registry_matching import match_registry_rules

ROOT = Path(__file__).resolve().parents[1]

REMEDIATION_PROMPT_TEMPLATE = """You are a network security engineer. A deterministic handler flagged one specific defect in this configuration.

Do NOT detect new issues. Do NOT assign or discuss CWEs beyond the flagged defect. Provide ONLY remediation for the flagged defect below.

Flagged defect:
- Rule: {rule_id}
- CWE: {cwe}
- Summary: {defect_summary}

Flagged configuration block:
```
{config_block}
```

Resolved object/group values for the flagged match:
{resolved_values}

Surrounding configuration context (other ACEs/rules, defined objects, interfaces in this file):
{surrounding_context}

Instructions:
- Recommend specific changes for THIS file only.
- State what to change and the exact target value.
- Reference ONLY object names, network literals, and addresses that appear in the configuration context above. Do not invent names.
- Do not quote evidence or cite line numbers.

Registry generic remediation (be more specific than this):
{registry_remediation}

Remediation:
"""


@dataclass(frozen=True)
class RemediationInstance:
    instance_id: str
    corpus: str
    rel_path: str
    target_type: str
    rule_id: str
    cwe: str
    defect_summary: str
    registry_remediation: str
    config_block: str
    resolved_values: str
    surrounding_context: str
    known_identifiers: tuple[str, ...]
    prompt: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _asa_surrounding_context(content: str, *, match_line: int) -> tuple[str, set[str]]:
    from shift_left.handlers.config.parsers.asa.parser import parse_asa_config

    parsed = parse_asa_config(content)
    known: set[str] = set()
    lines: list[str] = []

    if parsed.network_objects:
        lines.append("Network objects:")
        for obj in parsed.network_objects:
            known.add(obj.name)
            body = " ".join(obj.body_lines[:3])
            lines.append(f"  - {obj.name}: {body}")
    if parsed.network_object_groups:
        lines.append("Network object-groups:")
        for group in parsed.network_object_groups:
            known.add(group.name)
            members = ", ".join(
                f"{m.kind}:{m.ref or m.value or m.port}" for m in group.members[:8]
            )
            lines.append(f"  - {group.name}: {members}")
    if parsed.service_objects:
        lines.append("Service objects:")
        for obj in parsed.service_objects:
            known.add(obj.name)
            body = " ".join(obj.body_lines[:2])
            lines.append(f"  - {obj.name}: {body}")
    if parsed.service_object_groups:
        lines.append("Service object-groups:")
        for group in parsed.service_object_groups:
            known.add(group.name)
            members = ", ".join(
                f"{m.kind}:{m.ref or m.value or m.port}" for m in group.members[:8]
            )
            lines.append(f"  - {group.name}: {members}")
    if parsed.access_list_entries:
        lines.append("Other access-list entries:")
        for entry in parsed.access_list_entries:
            if entry.line_no == match_line:
                continue
            known.add(entry.acl_name)
            lines.append(f"  - {entry.acl_name} L{entry.line_no}: {entry.raw[:120]}")
    if parsed.management_access:
        lines.append("Management access:")
        for item in parsed.management_access:
            lines.append(
                f"  - {item.service} {item.network} {item.mask} interface {item.interface}"
            )
    if parsed.crypto_blocks:
        lines.append("Crypto blocks:")
        for block in parsed.crypto_blocks:
            known.add(block.name)
            lines.append(f"  - {block.kind} {block.name}: {' '.join(block.body_lines[:4])}")

    return "\n".join(lines) or "(no additional ASA context parsed)", known


def _ftd_surrounding_context(content: str, *, match_line_start: int, match_line_end: int) -> tuple[str, set[str]]:
    from shift_left.handlers.config.parsers.ftd.parser import parse_ftd_fmc_config

    parsed = parse_ftd_fmc_config(content)
    known: set[str] = set(parsed.defined_resource_addresses)
    lines: list[str] = []

    if parsed.network_symbols:
        lines.append("Defined network symbols:")
        for address, symbol in sorted(parsed.network_symbols.items()):
            known.add(address.split(".", 1)[-1] if "." in address else address)
            known.add(address)
            value = symbol.value or ", ".join(symbol.member_refs) or symbol.kind
            lines.append(f"  - {address} ({symbol.kind}): {value}")
    if parsed.port_objects:
        lines.append("Port objects:")
        for port in parsed.port_objects:
            known.add(port.name)
            lines.append(f"  - {port.name}: proto={port.protocol} port={port.port}")
    other_rules: list[str] = []
    for rule in parsed.access_rules:
        if rule.line_start <= match_line_end and rule.line_end >= match_line_start:
            continue
        known.add(rule.name)
        other_rules.append(
            f"  - {rule.name}: action={rule.action} src={','.join(rule.source_networks) or '-'} "
            f"dst={','.join(rule.destination_networks) or '-'}"
        )
    for bulk in parsed.access_rules_bulk:
        for rule in bulk.rules:
            if rule.line_start <= match_line_end and rule.line_end >= match_line_start:
                continue
            known.add(rule.name)
            other_rules.append(f"  - {rule.name}: action={rule.action}")
    if other_rules:
        lines.append("Other FMC access rules:")
        lines.extend(other_rules[:20])
    if parsed.vpn_ike_policies:
        lines.append("IKE policies:")
        for policy in parsed.vpn_ike_policies:
            known.add(policy.name)
            lines.append(
                f"  - {policy.name}: enc={','.join(policy.encryption)} "
                f"int={','.join(policy.integrity)} dh={policy.dh_group}"
            )

    return "\n".join(lines) or "(no additional FMC context parsed)", known


def _ios_xe_surrounding_context(content: str, *, match_line: int) -> tuple[str, set[str]]:
    from shift_left.handlers.config.parsers.ios_xe.parser import parse_ios_xe_config

    parsed = parse_ios_xe_config(content)
    known: set[str] = set()
    lines: list[str] = []

    if parsed.network_object_groups:
        lines.append("Network object-groups:")
        for group in parsed.network_object_groups:
            known.add(group.name)
            members = ", ".join(f"{m.kind}:{m.value}" for m in group.members[:8])
            lines.append(f"  - {group.name}: {members}")
    if parsed.service_object_groups:
        lines.append("Service object-groups:")
        for group in parsed.service_object_groups:
            known.add(group.name)
            members = ", ".join(f"{m.kind}:{m.value}" for m in group.members[:8])
            lines.append(f"  - {group.name}: {members}")
    if parsed.access_list_entries:
        lines.append("Other ACL entries:")
        for entry in parsed.access_list_entries:
            if entry.line_no == match_line:
                continue
            known.add(entry.acl_name)
            lines.append(f"  - {entry.acl_name} L{entry.line_no}: {entry.raw[:120]}")
    if parsed.interface_blocks:
        lines.append("Interface blocks:")
        for block in parsed.interface_blocks:
            known.add(block.name)
            body = " | ".join(block.body_lines[:6])
            lines.append(f"  - {block.name}: {body[:160]}")

    return "\n".join(lines) or "(no additional IOS-XE context parsed)", known


def _generic_surrounding_context(content: str) -> tuple[str, set[str]]:
    from shift_left.handlers.config.hcl_parse import parse_hcl_content

    status = parse_hcl_content(content)
    known: set[str] = set()
    if status.parsed is None:
        return f"(HCL parse unavailable: {status.error or 'unknown'})", known

    lines = [f"Parsed resource blocks: {status.resource_block_count}"]
    resource_blocks = status.parsed.get("resource")
    if isinstance(resource_blocks, dict):
        iterable = [
            (resource_type, resources)
            for resource_type, resources in resource_blocks.items()
        ]
    elif isinstance(resource_blocks, list):
        iterable = []
        for block in resource_blocks:
            if isinstance(block, dict):
                for resource_type, resources in block.items():
                    iterable.append((resource_type, resources))
    else:
        iterable = []

    for resource_type, resources in iterable:
        if not isinstance(resources, (list, dict)):
            continue
        items = resources if isinstance(resources, list) else [resources]
        for item in items[:15]:
            if not isinstance(item, dict):
                continue
            name = next(iter(item.keys()), "")
            known.add(str(name))
            lines.append(f"  - {resource_type}.{name}")
    return "\n".join(lines), known


def surrounding_context_for_match(
    *,
    target_type: str,
    content: str,
    match_line_start: int,
    match_line_end: int,
) -> tuple[str, set[str]]:
    if target_type == "cisco_secure_firewall":
        return _asa_surrounding_context(content, match_line=match_line_start)
    if target_type == "cisco_ftd":
        return _ftd_surrounding_context(
            content,
            match_line_start=match_line_start,
            match_line_end=match_line_end,
        )
    if target_type == "cisco_ios_xe":
        return _ios_xe_surrounding_context(content, match_line=match_line_start)
    return _generic_surrounding_context(content)


_CLI_NAME_PATTERNS = (
    re.compile(r"^\s*hostname\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*interface\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(
        r"^\s*object(?:-group)?\s+(?:network|service)\s+(\S+)",
        re.MULTILINE | re.IGNORECASE,
    ),
    re.compile(r"^\s*object\s+network\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*access-list\s+(\S+)", re.MULTILINE | re.IGNORECASE),
    re.compile(r'resource\s+"[^"]+"\s+"([^"]+)"', re.MULTILINE),
    re.compile(r"^\s*line\s+(\S+(?:\s+\d+(?:\s+\d+)?)?)", re.MULTILINE | re.IGNORECASE),
)


def _literal_identifiers(content: str) -> set[str]:
    literals: set[str] = set()
    for match in re.finditer(
        r"\b(?:\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?|0\.0\.0\.0/0|10\.\d+\.\d+\.\d+/\d+)\b",
        content,
    ):
        literals.add(match.group(0))
    for match in re.finditer(r'"([^"]{1,64})"', content):
        literals.add(match.group(1))
    for match in re.finditer(r"'([^']{1,64})'", content):
        literals.add(match.group(1))
    for pattern in _CLI_NAME_PATTERNS:
        for match in pattern.finditer(content):
            literals.add(match.group(1))
    for match in re.finditer(
        r"^\s*(?:transport input|name|policy-map|class-map)\s+(.+)$",
        content,
        re.MULTILINE | re.IGNORECASE,
    ):
        for token in re.split(r"\s+", match.group(1).strip()):
            if token and not token.isdigit():
                literals.add(token)
    return literals


def build_remediation_prompt(
    *,
    rule_id: str,
    cwe: str,
    defect_summary: str,
    registry_remediation: str,
    config_block: str,
    resolved_values: str,
    surrounding_context: str,
) -> str:
    return REMEDIATION_PROMPT_TEMPLATE.format(
        rule_id=rule_id,
        cwe=cwe,
        defect_summary=defect_summary,
        config_block=config_block.strip(),
        resolved_values=resolved_values.strip() or "(none)",
        surrounding_context=surrounding_context.strip() or "(none)",
        registry_remediation=registry_remediation.strip(),
    )


def build_instance(
    *,
    corpus: str,
    entry: CorpusEntry,
    rule_id: str,
    content: str,
    match: Any,
) -> RemediationInstance:
    rule = _RULE_BY_ID[rule_id]
    config_block = extract_config_block(content, match.line_start, match.line_end)
    resolved_values = resolved_values_for_match(
        target_type=entry.target_type,
        content=content,
        match=match,
    )
    surrounding_context, known = surrounding_context_for_match(
        target_type=entry.target_type,
        content=content,
        match_line_start=match.line_start,
        match_line_end=match.line_end,
    )
    known |= _literal_identifiers(content)
    known |= _literal_identifiers(config_block)
    known |= _literal_identifiers(surrounding_context)
    known |= _literal_identifiers(resolved_values)
    prompt = build_remediation_prompt(
        rule_id=rule_id,
        cwe=rule.cwe,
        defect_summary=rule.description,
        registry_remediation=rule.remediation,
        config_block=config_block,
        resolved_values=resolved_values,
        surrounding_context=surrounding_context,
    )
    return RemediationInstance(
        instance_id=f"{corpus}/{entry.rel_path}#{rule_id}",
        corpus=corpus,
        rel_path=entry.rel_path,
        target_type=entry.target_type,
        rule_id=rule_id,
        cwe=rule.cwe,
        defect_summary=rule.description,
        registry_remediation=rule.remediation,
        config_block=config_block,
        resolved_values=resolved_values,
        surrounding_context=surrounding_context,
        known_identifiers=tuple(sorted(known)),
        prompt=prompt,
    )


def build_remediation_instances() -> list[RemediationInstance]:
    instances: list[RemediationInstance] = []
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
