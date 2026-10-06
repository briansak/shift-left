"""Verify handler rules respect target_type scope and document legacy regex bleed."""

from __future__ import annotations

import re

from shift_left.handlers.config.parsers import invoke_parser
from shift_left.handlers.config.rules.registry import ALL_RULES, rules_for_target_type

ASA_SAMPLE = """
access-list OUTSIDE_IN extended permit ip any any
object service WIDE
 service tcp
"""

TF_SAMPLE = """
resource "aws_security_group_rule" "open" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
  from_port   = 22
  to_port     = 22
}
"""

FTD_SAMPLE = """
resource "fmc_port" "wide" {
  name     = "ANY_TCP"
  protocol = "TCP"
}
"""


def _rule_matches(rule, content: str) -> bool:
    matches = invoke_parser(
        rule.parser,
        chunk_content=content,
        line_offset=0,
        rule_id=rule.id,
        declared_target_type=rule.target_type,
    )
    return any(item.evaluation_status == "matched" for item in matches)


def _matched_rules(target_type: str, content: str) -> set[str]:
    matched: set[str] = set()
    for rule in rules_for_target_type(target_type):
        if _rule_matches(rule, content):
            matched.add(rule.id)
    return matched


def test_asa_rules_do_not_run_on_terraform_target_types() -> None:
    for target_type in ("generic_terraform", "cisco_ftd"):
        matched = _matched_rules(target_type, ASA_SAMPLE)
        assert not any(rule_id.startswith("ASA-") for rule_id in matched)


def test_tf_ftd_rules_do_not_run_on_asa_target_type() -> None:
    matched_tf = _matched_rules("cisco_secure_firewall", TF_SAMPLE)
    matched_ftd = _matched_rules("cisco_secure_firewall", FTD_SAMPLE)
    assert "TF-001" not in matched_tf
    assert not any(rule_id.startswith("FTD-") for rule_id in matched_ftd)


def _legacy_asa_001_regex_matches(text: str) -> bool:
    """Reconstruct deleted asa_acl.py whole-chunk matcher for scope analysis."""
    patterns = [
        r"any\s+any\s+(allow|permit)",
        r"(allow|permit)\s+\S+\s+any\s+any",
        r"(allow|permit)\s+ip\s+any\s+any",
        r"from\s+any\s+to\s+any\s+(allow|permit)",
        r"source\s*=\s*[\"']?0\.0\.0\.0/0[\"']?",
        r"permit\s+ip\s+any\s+any",
        r"access-list\s+\S+\s+extended\s+permit\s+ip\s+any\s+any",
    ]
    lowered = text.lower()
    if not any(re.search(pattern, lowered) for pattern in patterns):
        return False
    if "deny" in lowered and "allow" not in lowered and "permit" not in lowered:
        return False
    return "allow" in lowered or "permit" in lowered


def test_legacy_asa_001_regex_could_match_mixed_terraform_comments() -> None:
    """Pre-migration ASA-001 scanned whole chunk text; comments could satisfy permit+pattern."""
    terraform = """
resource "aws_security_group_rule" "open" {
  cidr_blocks = ["0.0.0.0/0"]
}
# emergency permit ip any any rollback
"""
    assert _legacy_asa_001_regex_matches(terraform)


def test_legacy_asa_001_regex_does_not_match_plain_terraform_without_permit_keyword() -> None:
    terraform = 'resource "x" { cidr_blocks = ["0.0.0.0/0"] }\n'
    assert not _legacy_asa_001_regex_matches(terraform)


def test_structural_asa_001_does_not_match_terraform() -> None:
    from shift_left.handlers.config.parsers.asa_config import match_asa_config_rules

    assert match_asa_config_rules(chunk_content=TF_SAMPLE, rule_id="ASA-001") == []


def test_enabled_rules_partitioned_by_target_type() -> None:
    asa_ids = {rule.id for rule in rules_for_target_type("cisco_secure_firewall")}
    ios_ids = {rule.id for rule in rules_for_target_type("cisco_ios_xe")}
    tf_ids = {rule.id for rule in rules_for_target_type("generic_terraform")}
    ftd_ids = {rule.id for rule in rules_for_target_type("cisco_ftd")}
    assert asa_ids.isdisjoint(tf_ids)
    assert asa_ids.isdisjoint(ftd_ids)
    assert asa_ids.isdisjoint(ios_ids)
    assert ios_ids.isdisjoint(tf_ids)
    assert ios_ids.isdisjoint(ftd_ids)
    assert tf_ids.isdisjoint(ftd_ids)
    enabled = {rule.id for rule in ALL_RULES if rule.enabled}
    assert asa_ids | ios_ids | tf_ids | ftd_ids <= enabled
