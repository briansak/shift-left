"""Declarative registry for deterministic config handler rules."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from shift_left.handlers.cwe_catalog import assert_cwe_in_catalog

RuleSeverity = Literal["block", "flag"]
RegistryRuleStatus = Literal["enabled", "disabled", "enforced_prematch"]

# Maps registry rule ids to config format handler names used during analysis.
RULE_HANDLER_NAMES: dict[str, frozenset[str]] = {
    "ASA-001": frozenset({"device", "generic"}),
    "ASA-002": frozenset({"device", "generic"}),
    "ASA-003": frozenset({"device", "generic"}),
    "ASA-004": frozenset({"device", "generic"}),
    "ASA-005": frozenset({"device", "generic"}),
    "ASA-006": frozenset({"device", "generic"}),
    "ASA-007": frozenset({"device", "generic"}),
    "IOS-001": frozenset({"device", "generic"}),
    "IOS-010": frozenset({"device", "generic"}),
    "NXOS-001": frozenset({"device", "generic"}),
    "NXOS-002": frozenset({"device", "generic"}),
    "NXOS-003": frozenset({"device", "generic"}),
    "NXOS-004": frozenset({"device", "generic"}),
    "NXOS-005": frozenset({"device", "generic"}),
    "NXOS-006": frozenset({"device", "generic"}),
    "NXOS-007": frozenset({"device", "generic"}),
    "NXOS-008": frozenset({"device", "generic"}),
    "NXOS-009": frozenset({"device", "generic"}),
    "NXOS-010": frozenset({"device", "generic"}),
    "IOS-002": frozenset({"device", "generic"}),
    "IOS-003": frozenset({"device", "generic"}),
    "IOS-004": frozenset({"device", "generic"}),
    "IOS-005": frozenset({"device", "generic"}),
    "IOS-006": frozenset({"device", "generic"}),
    "IOS-007": frozenset({"device", "generic"}),
    "IOS-008": frozenset({"device", "generic"}),
    "IOS-009": frozenset({"device", "generic"}),
    "FTD-001": frozenset({"terraform"}),
    "FTD-002": frozenset({"terraform"}),
    "FTD-003": frozenset({"terraform"}),
    "FTD-004": frozenset({"terraform"}),
    "FTD-005": frozenset({"terraform"}),
    "FTD-006": frozenset({"terraform"}),
    "FTD-007": frozenset({"terraform"}),
    "FTD-008": frozenset({"terraform"}),
    "FTD-009": frozenset({"terraform"}),
    "TF-001": frozenset({"terraform"}),
    "HCL-001": frozenset({"terraform"}),
    "HCL-002": frozenset({"terraform"}),
    "CLI-001": frozenset({"device", "generic"}),
}

# Corpus label for a CLI file with no managed target. Not a device platform.
UNDECLARED_TARGET_TYPE = "undeclared"
UNDETERMINED_PLATFORM_RULE_ID = "CLI-001"


@dataclass(frozen=True)
class Rule:
    id: str
    target_type: str
    cwe: str
    severity: RuleSeverity
    parser: str
    description: str
    remediation: str
    registry_status: RegistryRuleStatus = "enabled"
    waivable: bool = True
    # When registry_status=disabled, omit from coverage "rule gap" UI if not applicable.
    counts_as_coverage_gap: bool = True

    @property
    def enabled(self) -> bool:
        """True only for rules evaluated via the normal per-rule parser loop."""
        return self.registry_status == "enabled"


def rule_requires_fixture_coverage(rule: Rule) -> bool:
    """Rules that must appear in generated and holdout labeled corpora."""
    return rule.registry_status in ("enabled", "enforced_prematch")


def rule_registry_enforced(rule: Rule) -> bool:
    """Rules that participate in registry gate severity and waivers."""
    return rule.registry_status in ("enabled", "enforced_prematch")


ALL_RULES: tuple[Rule, ...] = (
    Rule(
        id="ASA-001",
        target_type="cisco_secure_firewall",
        cwe="CWE-284",
        severity="block",
        parser="asa_config",
        description="ASA ACL permits unrestricted any/any traffic.",
        remediation="Restrict source and destination to required networks and ports.",
    ),
    Rule(
        id="ASA-002",
        target_type="cisco_secure_firewall",
        cwe="CWE-284",
        severity="flag",
        parser="asa_config",
        description="Service object permits any protocol or unconstrained TCP/UDP.",
        remediation="Define service objects with explicit protocol and port constraints.",
    ),
    Rule(
        id="ASA-003",
        target_type="cisco_secure_firewall",
        cwe="CWE-778",
        severity="flag",
        parser="asa_config",
        description="Permit ACE does not include the log keyword.",
        remediation="Add the log keyword to permit ACEs that should emit syslog on match.",
        registry_status="disabled",
    ),
    Rule(
        id="ASA-004",
        target_type="cisco_secure_firewall",
        cwe="CWE-327",
        severity="block",
        parser="asa_config",
        description="IKEv2/IPsec proposal uses weak encryption, integrity, or DH group < 14.",
        remediation="Use AES-GCM or AES-256 with SHA-256+ and DH group 14 or higher.",
    ),
    Rule(
        id="ASA-005",
        target_type="cisco_secure_firewall",
        cwe="CWE-284",
        severity="block",
        parser="asa_config",
        description="Management plane access is permitted from non-RFC1918 sources.",
        remediation="Restrict ssh/http/https/telnet to RFC1918 management networks.",
    ),
    Rule(
        id="ASA-006",
        target_type="cisco_secure_firewall",
        cwe="CWE-693",
        severity="flag",
        parser="asa_config",
        description="Permit ACE is shadowed by a preceding deny ip any any.",
        remediation="Remove dead permit ACEs or reorder the ACL so intended permits are evaluated.",
    ),
    Rule(
        id="ASA-007",
        target_type="cisco_secure_firewall",
        cwe="CWE-754",
        severity="block",
        parser="asa_config",
        description=(
            "ASA access-list statement could not be parsed or resolved by the "
            "structural ACL parser."
        ),
        remediation=(
            "Rewrite as an extended ACE the parser supports, or extend managed-target "
            "coverage to include this ACL format."
        ),
        waivable=True,
    ),
    Rule(
        id="IOS-001",
        target_type="cisco_ios_xe",
        cwe="CWE-754",
        severity="block",
        parser="ios_xe_config",
        description=(
            "IOS-XE configuration statement could not be parsed or resolved by the "
            "structural CLI parser."
        ),
        remediation=(
            "Rewrite as an ACE or object-group the parser supports, fix undefined "
            "object-group references, or extend managed-target coverage."
        ),
        waivable=True,
    ),
    Rule(
        id="IOS-010",
        target_type="cisco_ios_xe",
        cwe="CWE-754",
        severity="block",
        parser="ios_xe_config",
        description=(
            "Declared managed target_type disagrees with platform sniffed from CLI content."
        ),
        remediation=(
            "Set the repository target_type to match the device platform sniffed from "
            "config markers (cisco_ios_xe, cisco_nx_os, or cisco_secure_firewall), or "
            "supply configuration for the declared platform."
        ),
        waivable=True,
    ),
    Rule(
        id="NXOS-001",
        target_type="cisco_nx_os",
        cwe="CWE-754",
        severity="block",
        parser="nx_os_config",
        description=(
            "NX-OS configuration statement could not be parsed or resolved by the "
            "structural CLI parser."
        ),
        remediation=(
            "Rewrite as an ACE or object-group the parser supports, fix undefined "
            "object-group references, or extend managed-target coverage."
        ),
        waivable=True,
    ),
    Rule(
        id="NXOS-002",
        target_type="cisco_nx_os",
        cwe="CWE-754",
        severity="block",
        parser="nx_os_config",
        description=(
            "Declared managed target_type disagrees with platform sniffed from CLI content."
        ),
        remediation=(
            "Set the repository target_type to match the device platform sniffed from "
            "config markers (cisco_nx_os, cisco_ios_xe, or cisco_secure_firewall), or "
            "supply configuration for the declared platform."
        ),
        waivable=True,
    ),
    Rule(
        id="NXOS-003",
        target_type="cisco_nx_os",
        cwe="CWE-319",
        severity="block",
        parser="nx_os_config",
        description="Cleartext telnet feature is enabled on the management plane.",
        remediation="Disable telnet with 'no feature telnet' and restrict VTY transport to SSH.",
    ),
    Rule(
        id="NXOS-004",
        target_type="cisco_nx_os",
        cwe="CWE-287",
        severity="block",
        parser="nx_os_config",
        description="SSH feature is disabled or absent while VTY lines are configured.",
        remediation="Enable 'feature ssh', disable telnet, and restrict VTY transport to SSH.",
    ),
    Rule(
        id="NXOS-005",
        target_type="cisco_nx_os",
        cwe="CWE-284",
        severity="block",
        parser="nx_os_config",
        description="SNMP uses default community strings or grants read-write access.",
        remediation=(
            "Replace public/private communities with unique credentials and restrict "
            "SNMP to read-only where possible."
        ),
    ),
    Rule(
        id="NXOS-006",
        target_type="cisco_nx_os",
        cwe="CWE-287",
        severity="block",
        parser="nx_os_config",
        description="AAA login authentication is not configured for VTY access.",
        remediation="Configure 'aaa authentication login' with centralized TACACS/RADIUS.",
    ),
    Rule(
        id="NXOS-007",
        target_type="cisco_nx_os",
        cwe="CWE-284",
        severity="block",
        parser="nx_os_config",
        description="Role definition grants broad permit command * privilege.",
        remediation="Scope role rules to explicit command sets instead of permit command *.",
    ),
    Rule(
        id="NXOS-008",
        target_type="cisco_nx_os",
        cwe="CWE-284",
        severity="block",
        parser="nx_os_config",
        description=(
            "Management VRF VTY access-class permits sources outside RFC1918 space."
        ),
        remediation=(
            "Restrict management VRF VTY access-class ACLs to RFC1918 jump-host networks."
        ),
    ),
    Rule(
        id="NXOS-009",
        target_type="cisco_nx_os",
        cwe="CWE-284",
        severity="block",
        parser="nx_os_config",
        description="ACL permit ACE allows any resolved source to any resolved destination.",
        remediation="Scope ACL permit ACEs to required source/destination networks and ports.",
    ),
    Rule(
        id="NXOS-010",
        target_type="cisco_nx_os",
        cwe="CWE-319",
        severity="block",
        parser="nx_os_config",
        description="Unencrypted file-transfer feature (FTP, TFTP, or SCP-server) is enabled.",
        remediation="Disable FTP/TFTP/SCP-server features or restrict to encrypted alternatives.",
    ),
    Rule(
        id="IOS-002",
        target_type="cisco_ios_xe",
        cwe="CWE-319",
        severity="block",
        parser="ios_xe_config",
        description="VTY line permits cleartext telnet transport.",
        remediation="Use transport input ssh (or restrict to ssh) on all VTY lines.",
    ),
    Rule(
        id="IOS-003",
        target_type="cisco_ios_xe",
        cwe="CWE-284",
        severity="block",
        parser="ios_xe_config",
        description="SNMP uses default community strings or grants read-write access.",
        remediation=(
            "Replace public/private communities with unique credentials and restrict "
            "SNMP to read-only where possible."
        ),
    ),
    Rule(
        id="IOS-004",
        target_type="cisco_ios_xe",
        cwe="CWE-287",
        severity="block",
        parser="ios_xe_config",
        description="AAA login is not configured or enable uses reversible type-7 password.",
        remediation=(
            "Configure aaa authentication login and replace enable password with enable secret."
        ),
    ),
    Rule(
        id="IOS-005",
        target_type="cisco_ios_xe",
        cwe="CWE-319",
        severity="block",
        parser="ios_xe_config",
        description="Cleartext management is enabled (HTTP server or password encryption disabled).",
        remediation="Disable ip http server and enable service password-encryption.",
    ),
    Rule(
        id="IOS-006",
        target_type="cisco_ios_xe",
        cwe="CWE-284",
        severity="block",
        parser="ios_xe_config",
        description="ACL permit ACE allows any resolved source to any resolved destination.",
        remediation="Scope ACL permits to required networks and services.",
    ),
    Rule(
        id="IOS-007",
        target_type="cisco_ios_xe",
        cwe="CWE-693",
        severity="flag",
        parser="ios_xe_config",
        description="Trunk uses native VLAN 1 or negotiates DTP in auto/desirable mode.",
        remediation=(
            "Set a dedicated native VLAN and use switchport nonegotiate on trunk interfaces."
        ),
    ),
    Rule(
        id="IOS-008",
        target_type="cisco_ios_xe",
        cwe="CWE-284",
        severity="block",
        parser="ios_xe_config",
        description="VTY access-class ACL permits non-RFC1918 sources.",
        remediation="Restrict VTY access-class ACLs to RFC1918 jump networks.",
    ),
    Rule(
        id="IOS-009",
        target_type="cisco_ios_xe",
        cwe="CWE-693",
        severity="flag",
        parser="ios_xe_config",
        description="Access port lacks BPDU guard and port-security hardening.",
        remediation=(
            "Enable spanning-tree bpduguard enable or switchport port-security on access ports."
        ),
        registry_status="disabled",
    ),
    Rule(
        id="FTD-001",
        target_type="cisco_ftd",
        cwe="CWE-284",
        severity="block",
        parser="ftd_fmc",
        description=(
            "FMC ALLOW rule uses missing or internet-wide source/destination "
            "network literals."
        ),
        remediation=(
            "Scope source_network_literals and destination_network_literals to "
            "required CIDRs; avoid any, 0.0.0.0/0, or omitted network sets on ALLOW rules."
        ),
    ),
    Rule(
        id="FTD-002",
        target_type="cisco_ftd",
        cwe="CWE-284",
        severity="flag",
        parser="ftd_fmc",
        description="FMC port object permits any protocol or unconstrained TCP/UDP.",
        remediation="Define fmc_port objects with explicit protocol and port constraints.",
    ),
    Rule(
        id="FTD-003",
        target_type="cisco_ftd",
        cwe="CWE-778",
        severity="flag",
        parser="ftd_fmc",
        description=(
            "FMC access rule ALLOW has no connection logging enabled "
            "(log_connection_begin / log_connection_end; log_begin accepted as alias)."
        ),
        remediation=(
            "Set log_connection_begin = true (and optionally log_connection_end = true) "
            "on ALLOW rules that require audit trails."
        ),
    ),
    Rule(
        id="FTD-004",
        target_type="cisco_ftd",
        cwe="CWE-327",
        severity="block",
        parser="ftd_fmc",
        description="FMC IKEv2 policy uses weak encryption, integrity, or DH group < 14.",
        remediation="Use AES-256 with SHA-256+ integrity and DH group 14 or higher in FMC VPN policies.",
    ),
    Rule(
        id="FTD-005",
        target_type="cisco_ftd",
        cwe="CWE-284",
        severity="block",
        parser="ftd_fmc",
        description="FMC ALLOW rule exposes management ports to non-RFC1918 sources.",
        remediation="Scope management access rules to RFC1918 jump-host networks.",
    ),
    Rule(
        id="FTD-006",
        target_type="cisco_ftd",
        cwe="CWE-693",
        severity="flag",
        parser="ftd_fmc",
        description=(
            "FMC ALLOW rule is shadowed by a catch-all BLOCK in the same "
            "fmc_access_rules ordered set (ASA-006 equivalent)."
        ),
        remediation="Remove dead ALLOW rules or reorder the fmc_access_rules items list.",
    ),
    Rule(
        id="FTD-007",
        target_type="cisco_ftd",
        cwe="CWE-693",
        severity="flag",
        parser="ftd_fmc",
        description=(
            "FMC ALLOW rule has no intrusion_policy_id (or legacy intrusion_policy) attached."
        ),
        remediation=(
            "Attach intrusion_policy_id to internet-facing ALLOW rules, or document "
            "an explicit exception when IPS is intentionally omitted."
        ),
        registry_status="disabled",
    ),
    Rule(
        id="FTD-008",
        target_type="cisco_ftd",
        cwe="CWE-754",
        severity="block",
        parser="ftd_fmc",
        description=(
            "FMC access rule references a network object resource that is not defined "
            "in the same Terraform module."
        ),
        remediation=(
            "Define the referenced fmc_network / fmc_host / fmc_network_group object "
            "in-module or replace the reference with network literals."
        ),
    ),
    Rule(
        id="FTD-009",
        target_type="cisco_ftd",
        cwe="CWE-657",
        severity="flag",
        parser="hcl_provider_coverage",
        description=(
            "Terraform resources use a provider prefix that no enabled FTD registry "
            "rule evaluates (coverage gap, not a configuration violation)."
        ),
        remediation=(
            "Add handler coverage for the provider, change target_type, or remove "
            "non-FMC provider resources from this module."
        ),
        waivable=True,
    ),
    Rule(
        id="TF-001",
        target_type="generic_terraform",
        cwe="CWE-284",
        severity="block",
        parser="terraform_hcl",
        description="Terraform resource allows internet-wide ingress (0.0.0.0/0 or equivalent).",
        remediation="Scope ingress CIDRs to required networks; avoid 0.0.0.0/0 on administrative or data ports.",
    ),
    Rule(
        id="HCL-001",
        target_type="generic_terraform",
        cwe="CWE-754",
        severity="block",
        parser="terraform_hcl",
        description=(
            "HCL/Terraform file could not be parsed or python-hcl2 is unavailable — "
            "the gate cannot interpret this content (applies to generic_terraform and cisco_ftd)."
        ),
        remediation=(
            "Fix HCL syntax, ensure python-hcl2 is installed in the gate environment, "
            "or waive with approve capability when the parse gap is accepted risk."
        ),
        registry_status="enforced_prematch",
        waivable=True,
        counts_as_coverage_gap=False,
    ),
    Rule(
        id="HCL-002",
        target_type="generic_terraform",
        cwe="CWE-657",
        severity="flag",
        parser="hcl_provider_coverage",
        description=(
            "Terraform resources use a provider prefix that no enabled registry rule "
            "evaluates (coverage gap, not a configuration violation)."
        ),
        remediation=(
            "Add handler coverage for the provider, change target_type, or remove "
            "resources outside aws_, azurerm_, google_, and fmc_ families."
        ),
        waivable=True,
    ),
    Rule(
        id=UNDETERMINED_PLATFORM_RULE_ID,
        target_type=UNDECLARED_TARGET_TYPE,
        cwe="CWE-754",
        severity="block",
        parser="undeclared_cli",
        description=(
            "Platform could not be determined from content. This file needs a managed "
            "target with a declared target_type under managed_targets.targets in "
            "shift-left.yaml."
        ),
        remediation=(
            "Add a managed_targets.targets entry in shift-left.yaml. "
            "Set target_type to cisco_secure_firewall, cisco_ios_xe, or cisco_nx_os, "
            "and set config_paths so they cover this file:\n"
            "managed_targets:\n"
            "  targets:\n"
            "    - id: edge-fw-01\n"
            "      display_name: edge-fw-01\n"
            "      target_type: cisco_ios_xe\n"
            "      repo: owner/repo\n"
            "      branch: main\n"
            "      config_paths:\n"
            "        - \"configs/**/*.cfg\""
        ),
        registry_status="enforced_prematch",
        waivable=False,
        counts_as_coverage_gap=False,
    ),
)


def rules_for_target_type(target_type: str) -> list[Rule]:
    """Return registry rules that run in the per-rule parser loop for a target type."""
    return [
        rule
        for rule in ALL_RULES
        if rule.registry_status == "enabled" and rule.target_type == target_type
    ]


def rule_by_id(rule_id: str) -> Rule | None:
    for rule in ALL_RULES:
        if rule.id == rule_id:
            return rule
    return None


def rules_for_handler(handler_name: str) -> list[Rule]:
    """Return enabled registry rules that apply to a config format handler."""
    return [
        rule
        for rule in ALL_RULES
        if rule.registry_status == "enabled"
        and handler_name in RULE_HANDLER_NAMES.get(rule.id, frozenset())
    ]


def evaluated_rule_ids() -> list[str]:
    """Registry rules included in corpus eval metrics (enabled + enforced_prematch)."""
    return sorted(rule.id for rule in ALL_RULES if rule_requires_fixture_coverage(rule))


def rule_counts_by_target_type() -> dict[str, int]:
    """Count enabled rules per managed target type (for UI introspection)."""
    counts: dict[str, int] = {}
    for rule in ALL_RULES:
        if rule.registry_status != "enabled":
            continue
        counts[rule.target_type] = counts.get(rule.target_type, 0) + 1
    return counts


def validate_config_rules(rules: tuple[Rule, ...] = ALL_RULES) -> None:
    for rule in rules:
        assert_cwe_in_catalog(rule.cwe, rule_id=rule.id)
