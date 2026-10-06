"""Deterministic Terraform unrestricted-ingress rules via python-hcl2 parsing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

import hcl2

from shift_left.handlers.config.types import ConfigRuleMatch

EvaluationStatus = Literal["matched", "unevaluated"]

_OPEN_SOURCE_VALUES = frozenset({"*", "0.0.0.0/0", "::/0", "internet", "any"})
_AWS_INGRESS_RESOURCES = frozenset(
    {
        "aws_security_group",
        "aws_security_group_rule",
        "aws_vpc_security_group_ingress_rule",
    }
)
_AZURE_INGRESS_RESOURCES = frozenset(
    {
        "azurerm_network_security_rule",
        "azurerm_network_security_group",
    }
)
_GCP_INGRESS_RESOURCES = frozenset({"google_compute_firewall"})
_FMC_RESOURCES = frozenset({"fmc_access_rule", "fmc_access_policies", "fmc_access_policy"})


@dataclass(frozen=True)
class TerraformRuleSpec:
    id: str
    provider: str
    resource_types: frozenset[str]
    attribute_condition: str
    cwe: str
    description: str
    covers: tuple[str, ...]
    does_not_cover: tuple[str, ...]


TERRAFORM_RULE_SPECS: tuple[TerraformRuleSpec, ...] = (
    TerraformRuleSpec(
        id="terraform/aws-unrestricted-ingress",
        provider="aws",
        resource_types=_AWS_INGRESS_RESOURCES,
        attribute_condition="cidr_blocks/ipv6_cidr_blocks/cidr_ipv4/cidr_ipv6 contains 0.0.0.0/0 or ::/0 on ingress",
        cwe="CWE-284",
        description="AWS security group ingress allows internet-wide source CIDR.",
        covers=("aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule"),
        does_not_cover=("azurerm_*", "google_compute_*", "fmc_*"),
    ),
    TerraformRuleSpec(
        id="terraform/azure-unrestricted-ingress",
        provider="azure",
        resource_types=_AZURE_INGRESS_RESOURCES,
        attribute_condition="source_address_prefix is *, 0.0.0.0/0, or Internet with Allow inbound",
        cwe="CWE-284",
        description="Azure NSG rule allows unrestricted inbound source.",
        covers=("azurerm_network_security_rule", "azurerm_network_security_group.security_rule"),
        does_not_cover=("aws_*", "google_compute_*", "fmc_*"),
    ),
    TerraformRuleSpec(
        id="terraform/gcp-unrestricted-ingress",
        provider="gcp",
        resource_types=_GCP_INGRESS_RESOURCES,
        attribute_condition="source_ranges contains 0.0.0.0/0 on INGRESS firewall",
        cwe="CWE-284",
        description="GCP firewall allows internet-wide ingress source range.",
        covers=("google_compute_firewall",),
        does_not_cover=("aws_*", "azurerm_*", "fmc_*"),
    ),
    TerraformRuleSpec(
        id="terraform/fmc-unrestricted-ingress",
        provider="cisco-fmc",
        resource_types=_FMC_RESOURCES,
        attribute_condition="ALLOW without network/port scoping or default_action ALLOW",
        cwe="CWE-284",
        description="FMC access rule or policy permits unrestricted allow.",
        covers=("fmc_access_rule", "fmc_access_policy"),
        does_not_cover=("aws_*", "azurerm_*", "google_compute_*"),
    ),
)


def _strip_quotes(value: Any) -> str:
    if not isinstance(value, str):
        return str(value)
    text = value.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _is_unevaluated(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_is_unevaluated(item) for item in value.values())
    if isinstance(value, list):
        return any(_is_unevaluated(item) for item in value)
    if not isinstance(value, str):
        return False
    text = value.strip()
    return text.startswith("${") or text.startswith("var.") or "${" in text


def _is_open_cidr(value: Any) -> bool:
    if _is_unevaluated(value):
        return False
    text = _strip_quotes(value).strip().lower()
    return text in _OPEN_SOURCE_VALUES


def _cidr_list_has_open(values: Any) -> tuple[bool, bool]:
    """Return (matched_open, unevaluated)."""
    if _is_unevaluated(values):
        return False, True
    unevaluated = False
    for item in _as_list(values):
        if _is_unevaluated(item):
            unevaluated = True
            continue
        if _is_open_cidr(item):
            return True, unevaluated
    return False, unevaluated


def _find_resource_line_range(
    content: str,
    resource_type: str,
    resource_name: str,
) -> tuple[int, int]:
    lines = content.splitlines()
    header = re.compile(
        rf'^\s*resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"',
        re.IGNORECASE,
    )
    start_idx = None
    for index, line in enumerate(lines):
        if header.match(line):
            start_idx = index
            break
    if start_idx is None:
        return 1, max(1, len(lines))
    depth = 0
    end_idx = start_idx
    for index in range(start_idx, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        end_idx = index
        if index > start_idx and depth <= 0:
            break
    return start_idx + 1, end_idx + 1


def _match_for_rule_id(rule_id: str) -> TerraformRuleSpec:
    for spec in TERRAFORM_RULE_SPECS:
        if spec.id == rule_id:
            return spec
    raise KeyError(rule_id)


def _hit(
    *,
    rule_id: str,
    content: str,
    resource_type: str,
    resource_name: str,
    status: EvaluationStatus,
    detail: str,
    line_offset: int = 0,
) -> ConfigRuleMatch:
    spec = _match_for_rule_id(rule_id)
    start, end = _find_resource_line_range(content, resource_type, resource_name)
    return ConfigRuleMatch(
        cwe=spec.cwe,
        pattern_id=rule_id,
        line_start=start + line_offset,
        line_end=end + line_offset,
        evaluation_status=status,
        title=f"Unrestricted ingress ({spec.provider})",
        description=detail,
        construct_key=f"resource:{resource_type.lower()}.{resource_name.lower()}",
    )


def _aws_ingress_attrs(attrs: dict[str, Any]) -> tuple[bool, bool]:
    matched = False
    unevaluated = False
    rule_type = _strip_quotes(attrs.get("type", "")).lower()
    if rule_type and rule_type not in {"ingress", ""}:
        return False, False
    for key in ("cidr_blocks", "ipv6_cidr_blocks", "cidr_ipv4", "cidr_ipv6"):
        open_hit, uneval = _cidr_list_has_open(attrs.get(key))
        matched = matched or open_hit
        unevaluated = unevaluated or uneval
    for ingress_block in _as_list(attrs.get("ingress")):
        if not isinstance(ingress_block, dict):
            continue
        open_hit, uneval = _aws_ingress_attrs(ingress_block)
        matched = matched or open_hit
        unevaluated = unevaluated or uneval
    return matched, unevaluated


def _azure_rule_attrs(attrs: dict[str, Any]) -> tuple[bool, bool]:
    access = _strip_quotes(attrs.get("access", "Allow")).lower()
    direction = _strip_quotes(attrs.get("direction", "Inbound")).lower()
    if access != "allow" or direction not in {"inbound", ""}:
        return False, False
    prefix = attrs.get("source_address_prefix")
    prefixes = attrs.get("source_address_prefixes")
    if _is_unevaluated(prefix) or _is_unevaluated(prefixes):
        return False, True
    if _is_open_cidr(prefix):
        return True, False
    for item in _as_list(prefixes):
        if _is_open_cidr(item):
            return True, False
    return False, False


def _gcp_firewall_attrs(attrs: dict[str, Any]) -> tuple[bool, bool]:
    direction = _strip_quotes(attrs.get("direction", "INGRESS")).upper()
    if direction and direction != "INGRESS":
        return False, False
    open_hit, unevaluated = _cidr_list_has_open(attrs.get("source_ranges"))
    return open_hit, unevaluated


def _fmc_literal_values(block: Any) -> list[str]:
    values: list[str] = []
    for entry in _as_list(block):
        if not isinstance(entry, dict):
            continue
        for literal in _as_list(entry.get("literal")):
            if isinstance(literal, dict) and "value" in literal:
                values.append(_strip_quotes(literal["value"]))
    return values


def _fmc_rule_attrs(attrs: dict[str, Any]) -> tuple[bool, bool]:
    action = _strip_quotes(attrs.get("action", "")).upper()
    if action != "ALLOW":
        return False, False
    if attrs.get("enabled") is False:
        return False, False

    unevaluated = False
    for key in (
        "source_network_literals",
        "destination_network_literals",
        "source_port_literals",
        "destination_port_literals",
    ):
        if _is_unevaluated(attrs.get(key)):
            unevaluated = True

    sources = _fmc_literal_values(attrs.get("source_network_literals"))
    dests = _fmc_literal_values(attrs.get("destination_network_literals"))
    src_ports = _fmc_literal_values(attrs.get("source_port_literals"))
    dest_ports = _fmc_literal_values(attrs.get("destination_port_literals"))

    open_source = not sources or any(value.lower() in _OPEN_SOURCE_VALUES for value in sources)
    open_dest = not dests or any(value.lower() in {"any", "*"} for value in dests)
    open_ports = (not src_ports or any(value.lower() in {"any", "*"} for value in src_ports)) and (
        not dest_ports or any(value.lower() in {"any", "*"} for value in dest_ports)
    )
    if open_source and open_dest and open_ports:
        return True, unevaluated
    if sources and any(value.lower() in _OPEN_SOURCE_VALUES for value in sources):
        return True, unevaluated
    return False, unevaluated


def _fmc_policy_attrs(attrs: dict[str, Any]) -> tuple[bool, bool]:
    default_action = _strip_quotes(attrs.get("default_action", "")).upper()
    if _is_unevaluated(attrs.get("default_action")):
        return False, True
    if default_action == "ALLOW":
        return True, False
    return False, False


def _evaluate_resource(
    *,
    content: str,
    resource_type: str,
    resource_name: str,
    attrs: dict[str, Any],
    line_offset: int,
) -> list[ConfigRuleMatch]:
    hits: list[ConfigRuleMatch] = []
    matched = False
    unevaluated = False

    if resource_type in _AWS_INGRESS_RESOURCES:
        matched, unevaluated = _aws_ingress_attrs(attrs)
        rule_id = "terraform/aws-unrestricted-ingress"
        detail = "AWS ingress allows 0.0.0.0/0 or ::/0."
    elif resource_type == "azurerm_network_security_rule":
        matched, unevaluated = _azure_rule_attrs(attrs)
        rule_id = "terraform/azure-unrestricted-ingress"
        detail = "Azure NSG rule allows unrestricted inbound source."
    elif resource_type == "azurerm_network_security_group":
        for rule_block in _as_list(attrs.get("security_rule")):
            if isinstance(rule_block, dict):
                sub_matched, sub_uneval = _azure_rule_attrs(rule_block)
                matched = matched or sub_matched
                unevaluated = unevaluated or sub_uneval
        rule_id = "terraform/azure-unrestricted-ingress"
        detail = "Azure NSG security_rule allows unrestricted inbound source."
    elif resource_type == "google_compute_firewall":
        matched, unevaluated = _gcp_firewall_attrs(attrs)
        rule_id = "terraform/gcp-unrestricted-ingress"
        detail = "GCP firewall source_ranges includes 0.0.0.0/0."
    elif resource_type == "fmc_access_rule":
        matched, unevaluated = _fmc_rule_attrs(attrs)
        rule_id = "terraform/fmc-unrestricted-ingress"
        detail = "FMC access rule ALLOW without adequate network/port scoping."
    elif resource_type == "fmc_access_policy":
        matched, unevaluated = _fmc_policy_attrs(attrs)
        rule_id = "terraform/fmc-unrestricted-ingress"
        detail = "FMC access policy default_action is ALLOW."
    else:
        return hits

    if unevaluated and not matched:
        hits.append(
            _hit(
                rule_id=rule_id,
                content=content,
                resource_type=resource_type,
                resource_name=resource_name,
                status="unevaluated",
                detail=f"{detail} Source CIDR/network is interpolated — unevaluated.",
                line_offset=line_offset,
            )
        )
    elif matched:
        hits.append(
            _hit(
                rule_id=rule_id,
                content=content,
                resource_type=resource_type,
                resource_name=resource_name,
                status="matched",
                detail=detail,
                line_offset=line_offset,
            )
        )
    return hits


def _iter_resources(parsed: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    resources: list[tuple[str, str, dict[str, Any]]] = []
    for block in _as_list(parsed.get("resource")):
        if not isinstance(block, dict):
            continue
        for raw_type, instances in block.items():
            resource_type = _strip_quotes(raw_type)
            if not isinstance(instances, dict):
                continue
            for raw_name, attrs in instances.items():
                resource_name = _strip_quotes(raw_name)
                if isinstance(attrs, dict):
                    resources.append((resource_type, resource_name, attrs))
    return resources


def match_terraform_hcl_rules(
    *,
    chunk_content: str,
    line_offset: int = 0,
) -> list[ConfigRuleMatch]:
    """
    Parse Terraform with python-hcl2 and return deterministic handler matches.

    Returns unevaluated hits when CIDR/network values are interpolated.
    """
    try:
        parsed = hcl2.loads(chunk_content)
    except Exception as exc:  # noqa: BLE001
        return [
            ConfigRuleMatch(
                cwe="CWE-284",
                pattern_id="terraform/parse-limitation",
                line_start=1 + line_offset,
                line_end=max(1, len(chunk_content.splitlines())) + line_offset,
                evaluation_status="unevaluated",
                title="Terraform parse limitation",
                description=f"HCL could not be parsed deterministically: {exc}",
            )
        ]

    hits: list[ConfigRuleMatch] = []
    for resource_type, resource_name, attrs in _iter_resources(parsed):
        hits.extend(
            _evaluate_resource(
                content=chunk_content,
                resource_type=resource_type,
                resource_name=resource_name,
                attrs=attrs,
                line_offset=line_offset,
            )
        )
    return hits
