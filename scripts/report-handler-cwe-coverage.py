#!/usr/bin/env python3
"""Report handler_asserted_cwe coverage for fixtures and corpus entries."""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
FSEC = ROOT / "services" / "foundation-sec-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ORCH, FSEC):
    sys.path.insert(0, str(path))

from foundation_sec_server.analyzer import ConfigAnalyzer  # noqa: E402
from foundation_sec_server.engine import ScriptedEvalEngine  # noqa: E402
from foundation_sec_server.handlers.cwe_rules import CONFIG_HANDLER_RULES, match_handler_cwe  # noqa: E402
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY  # noqa: E402
from shift_left.handlers.config.parsers.terraform_hcl import TERRAFORM_RULE_SPECS  # noqa: E402

BEFORE_UNCLASSIFIED_RATE = 0.75

PERMISSIVE_FIREWALL = "access-list OUT extended permit ip any any\n"
LEAST_PRIVILEGE_FIREWALL = textwrap.dedent(
    """\
    access-list OUT extended permit tcp 10.0.1.0/24 10.0.2.0/24 eq 443
    access-list OUT extended deny ip any any
    """
)
PERMISSIVE_TERRAFORM = textwrap.dedent(
    """\
    resource "aws_security_group_rule" "wide_ingress" {
      type              = "ingress"
      from_port         = 0
      to_port           = 65535
      protocol          = "-1"
      cidr_blocks       = ["0.0.0.0/0"]
      security_group_id = aws_security_group.app.id
    }
    """
)
SCOPED_TERRAFORM = textwrap.dedent(
    """\
    resource "aws_security_group_rule" "app_https" {
      type              = "ingress"
      from_port         = 443
      to_port           = 443
      protocol          = "tcp"
      cidr_blocks       = ["10.0.0.0/8"]
      security_group_id = aws_security_group.app.id
    }
    """
)

FIXTURES = [
    ("firewall_permissive", "firewall/asa.rules", PERMISSIVE_FIREWALL, True),
    ("firewall_least_privilege", "firewall/asa.rules", LEAST_PRIVILEGE_FIREWALL, False),
    ("terraform_permissive", "infra/main.tf", PERMISSIVE_TERRAFORM, True),
    ("terraform_scoped", "infra/main.tf", SCOPED_TERRAFORM, False),
]

EXPECTED_RULE_BY_CORPUS = {
    "bad/terraform-open-sg.tf": "terraform/aws-unrestricted-ingress",
    "bad/k8s-hostnetwork.yaml": "kubernetes/hostnetwork",
    "bad/ansible-wildcard-sudo.yml": "ansible/wildcard-sudo",
    "bad/firewall-any-any.rules": "firewall/permissive-any-any",
    "bad/nginx-no-tls.conf": "nginx/plaintext-listener",
}


def handler_path(rel: str) -> str:
    name = Path(rel).name
    if name.endswith(".rules") or "firewall" in rel:
        return f"firewall/{name}"
    if name.endswith(".tf"):
        return f"infra/{name}"
    if name.endswith((".yaml", ".yml")) and "k8s" in rel:
        return f"deploy/{name}"
    if name.endswith((".yaml", ".yml")):
        return f"ansible/{name}"
    if name.endswith(".conf"):
        return f"nginx/{name}"
    return rel


def match_rule_id(*, chunk_content: str, handler) -> str | None:
    match = match_handler_cwe(chunk_content=chunk_content, handler=handler)
    return match.pattern_id if match else None


def evaluate_rule_precision(
    *,
    rule_id: str,
    positives: list[tuple[str, str, str]],
    negatives: list[tuple[str, str, str]],
) -> dict:
    tp = fp = fn = 0
    false_positive_items: list[str] = []
    for rel, path, content in positives:
        handler = DEFAULT_REGISTRY.resolve(path)
        matched = match_rule_id(chunk_content=content, handler=handler)
        if matched == rule_id:
            tp += 1
        else:
            fn += 1
    for rel, path, content in negatives:
        handler = DEFAULT_REGISTRY.resolve(path)
        matched = match_rule_id(chunk_content=content, handler=handler)
        if matched == rule_id:
            fp += 1
            false_positive_items.append(rel)
    precision = round(tp / (tp + fp), 3) if (tp + fp) else None
    return {
        "rule_id": rule_id,
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "false_positive_items": false_positive_items,
    }


def main() -> int:
    engine = ScriptedEvalEngine()
    analyzer = ConfigAnalyzer(engine)

    fixture_rows = []
    for name, path, content, expect_match in FIXTURES:
        handler = DEFAULT_REGISTRY.resolve(path)
        match = match_handler_cwe(chunk_content=content, handler=handler)
        result = analyzer.analyze_files(
            [{"path": path, "hunks": [{"new_start": 1, "new_end": 1, "content": content}]}]
        )
        findings = result.get("findings") or []
        fixture_rows.append(
            {
                "case": name,
                "handler_asserted_cwe": match.cwe if match else None,
                "finding_handler_cwes": [
                    item.get("handler_asserted_cwe") for item in findings
                ],
                "classified": bool(match),
                "expect_match": expect_match,
            }
        )

    corpus_path = ROOT / "validation" / "corpus" / "manifest.json"
    corpus_rows = []
    positives: list[tuple[str, str, str]] = []
    negatives: list[tuple[str, str, str]] = []
    if corpus_path.exists():
        manifest = json.loads(corpus_path.read_text())
        for entry in manifest.get("entries", []):
            rel = entry.get("path") or entry.get("file") or ""
            path = handler_path(str(rel))
            content_path = ROOT / "validation" / "corpus" / rel
            if not content_path.exists():
                continue
            content = content_path.read_text()
            handler = DEFAULT_REGISTRY.resolve(path)
            match = match_handler_cwe(chunk_content=content, handler=handler)
            expect_flagged = bool(entry.get("expect_flagged"))
            row = {
                "path": rel,
                "handler_asserted_cwe": match.cwe if match else None,
                "pattern_id": match.pattern_id if match else None,
                "classified": bool(match),
                "expect_flagged": expect_flagged,
                "expected_rule": EXPECTED_RULE_BY_CORPUS.get(str(rel)),
            }
            corpus_rows.append(row)
            item = (str(rel), path, content)
            if expect_flagged:
                positives.append(item)
            else:
                negatives.append(item)

    total = len(fixture_rows) + len(corpus_rows)
    classified = sum(1 for row in fixture_rows + corpus_rows if row["classified"])
    unclassified_rate = round((total - classified) / total, 3) if total else 0.0

    rule_precision = []
    all_rule_ids = [rule.id for rule in CONFIG_HANDLER_RULES] + [spec.id for spec in TERRAFORM_RULE_SPECS]
    for rule_id in all_rule_ids:
        rule_positives = [
            item
            for item in positives
            if EXPECTED_RULE_BY_CORPUS.get(item[0]) == rule_id
        ]
        rule_precision.append(
            evaluate_rule_precision(
                rule_id=rule_id,
                positives=rule_positives,
                negatives=negatives,
            )
        )

    report = {
        "fixtures": fixture_rows,
        "corpus": corpus_rows,
        "summary": {
            "total_entries": total,
            "handler_classified": classified,
            "unclassified": total - classified,
            "unclassified_rate": unclassified_rate,
            "before_unclassified_rate": BEFORE_UNCLASSIFIED_RATE,
            "delta_unclassified_rate": round(unclassified_rate - BEFORE_UNCLASSIFIED_RATE, 3),
        },
        "rule_precision": rule_precision,
    }
    out = ROOT / "validation" / "reports" / "handler-cwe-coverage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
