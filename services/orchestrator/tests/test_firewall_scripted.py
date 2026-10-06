"""Deterministic firewall posture tests via ScriptedEvalEngine."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FOUNDATION_SEC_ENGINE", "scripted")

from foundation_sec_server.analyzer import ConfigAnalyzer
from foundation_sec_server.engine import ScriptedEvalEngine
from foundation_sec_server.handlers.registry import DEVICE_CONFIG


PERMISSIVE_FIREWALL = """\
access-list OUT extended permit ip any any
"""

LEAST_PRIVILEGE_FIREWALL = """\
access-list OUT extended permit tcp 10.0.1.0/24 10.0.2.0/24 eq 443
access-list OUT extended deny ip any any
"""

PERMISSIVE_TERRAFORM = """\
resource "aws_security_group_rule" "wide_ingress" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.app.id
}
"""

SCOPED_TERRAFORM = """\
resource "aws_security_group_rule" "app_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.app.id
}
"""


@pytest.fixture
def analyzer() -> ConfigAnalyzer:
    return ConfigAnalyzer(ScriptedEvalEngine(), max_context_tokens=8192)


def test_permissive_any_any_firewall_flagged(analyzer: ConfigAnalyzer) -> None:
    result = analyzer.analyze_files(
        [
            {
                "path": "firewall/asa.rules",
                "hunks": [{"new_start": 1, "new_end": 1, "content": PERMISSIVE_FIREWALL}],
            }
        ]
    )
    findings = result["findings"]
    assert result["outcome"] in {"completed_with_findings", "completed_no_findings"}
    assert findings, "expected permissive any/any ALLOW to be flagged"
    assert any("any/any" in f.get("title", "").lower() or "0.0.0.0/0" in f.get("title", "") for f in findings)
    assert all(f.get("cwe") == "CWE-284" for f in findings)


def test_least_privilege_firewall_not_flagged(analyzer: ConfigAnalyzer) -> None:
    result = analyzer.analyze_files(
        [
            {
                "path": "firewall/asa.rules",
                "hunks": [{"new_start": 1, "new_end": 2, "content": LEAST_PRIVILEGE_FIREWALL}],
            }
        ]
    )
    assert not result["findings"], "scoped ruleset should not trigger permissive firewall heuristics"


def test_terraform_global_ingress_flagged(analyzer: ConfigAnalyzer) -> None:
    result = analyzer.analyze_files(
        [
            {
                "path": "infra/main.tf",
                "hunks": [{"new_start": 1, "new_end": 8, "content": PERMISSIVE_TERRAFORM}],
            }
        ]
    )
    findings = result["findings"]
    assert findings
    assert any("terraform" in f.get("title", "").lower() for f in findings)


def test_terraform_scoped_rule_not_flagged(analyzer: ConfigAnalyzer) -> None:
    result = analyzer.analyze_files(
        [
            {
                "path": "infra/main.tf",
                "hunks": [{"new_start": 1, "new_end": 8, "content": SCOPED_TERRAFORM}],
            }
        ]
    )
    assert not result["findings"]


def test_device_handler_matches_firewall_path() -> None:
    assert DEVICE_CONFIG.matches("firewall/asa.rules")
