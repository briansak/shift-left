"""Undeclared device-handler findings follow the platform sniff.

The labeled corpora exercise ``match_registry_rules`` with a declared target type.
A device chunk with no declaration goes through ``match_handler_cwes``. A known
sniff keeps only that platform's rules. An unknown sniff emits one undetermined-
platform finding and does not run ASA, IOS-XE, or NX-OS rules.
"""

from __future__ import annotations

import sys
from pathlib import Path

from foundation_sec_server.handlers.cwe_rules import (
    UNDETERMINED_PLATFORM_CWE,
    UNDETERMINED_PLATFORM_RULE_ID,
    UNDETERMINED_PLATFORM_SEVERITY,
    match_handler_cwes,
)
from foundation_sec_server.handlers.registry import DEVICE_CONFIG
from shift_left.handlers.config.parsers.ios_xe.platform import SniffedPlatform, sniff_platform
from shift_left.handlers.config.registry_matching import match_registry_rules
from shift_left.handlers.config.rules.registry import rule_by_id

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from validation.eval_handlers import (  # noqa: E402
    GENERATED_CORPUS_DIR,
    HOLDOUT_CORPUS_DIR,
    load_corpus,
)

CLI_PLATFORMS = (
    "cisco_secure_firewall",
    "cisco_ios_xe",
    "cisco_nx_os",
)

# Still no ASA-specific marker. crypto ikev2 / transform-set are shared with IOS-XE,
# and the .cfg is generic IOS-shaped text outside the ASA parser.
UNDETERMINED_CORPUS_FILES = frozenset(
    {
        "generated:cisco_secure_firewall/legacy-transform-strong.rules",
        "holdout:cisco_secure_firewall/holdout-asa-nonrules-cfg.cfg",
    }
)

_PLATFORM_PREFIXES = ("ASA-", "IOS-", "NXOS-")


def _undeclared_findings(content: str) -> frozenset[tuple[str, int]]:
    findings: set[tuple[str, int]] = set()
    for match in match_handler_cwes(chunk_content=content, handler=DEVICE_CONFIG):
        if match.evaluation_status != "matched":
            continue
        if (
            match.pattern_id != UNDETERMINED_PLATFORM_RULE_ID
            and rule_by_id(match.pattern_id) is None
        ):
            continue
        findings.add((match.pattern_id, match.line_start or 1))
    return frozenset(findings)


def _declared_findings(target_type: str, content: str) -> frozenset[tuple[str, int]]:
    return frozenset(
        (match.rule_id, match.line_start) for match in match_registry_rules(target_type, content)
    )


def test_undeclared_device_path_matches_declared_platform_on_cli_corpus() -> None:
    mismatches: list[str] = []
    unknown: list[str] = []
    seen = 0
    for corpus_name, corpus_dir in (
        ("generated", GENERATED_CORPUS_DIR),
        ("holdout", HOLDOUT_CORPUS_DIR),
    ):
        for entry in load_corpus(corpus_dir):
            if entry.target_type not in CLI_PLATFORMS:
                continue
            seen += 1
            content = (corpus_dir / entry.rel_path).read_text()
            sniffed = sniff_platform(content)
            got = _undeclared_findings(content)
            key = f"{corpus_name}:{entry.rel_path}"
            if sniffed == SniffedPlatform.UNKNOWN:
                unknown.append(key)
                expected = frozenset({(UNDETERMINED_PLATFORM_RULE_ID, 1)})
                platform_label = "unknown"
                for rule_id, _line in got:
                    if rule_id.startswith(_PLATFORM_PREFIXES):
                        mismatches.append(f"{key}: unknown sniff still emitted {rule_id}")
            else:
                expected = _declared_findings(sniffed.value, content)
                platform_label = sniffed.value
                for rule_id, line in sorted(got):
                    rule = rule_by_id(rule_id)
                    if rule is not None and rule.target_type == sniffed.value:
                        continue
                    mismatches.append(
                        f"{key}: {rule_id} line {line} is not a {sniffed.value} rule"
                    )
            if got != expected:
                mismatches.append(
                    f"{key}: sniff={platform_label} label={entry.target_type}\n"
                    f"  undeclared only: {sorted(got - expected)}\n"
                    f"  declared only: {sorted(expected - got)}"
                )
    assert seen > 0
    assert not mismatches, "undeclared device path mismatches:\n" + "\n".join(mismatches)
    assert set(unknown) == UNDETERMINED_CORPUS_FILES


def test_unknown_sniff_emits_one_undetermined_platform_finding() -> None:
    content = "aaa new-model\nline vty 0 4\n"
    assert sniff_platform(content) == SniffedPlatform.UNKNOWN
    matches = [
        match
        for match in match_handler_cwes(chunk_content=content, handler=DEVICE_CONFIG)
        if match.evaluation_status == "matched"
    ]
    assert len(matches) == 1
    finding = matches[0]
    assert finding.pattern_id == UNDETERMINED_PLATFORM_RULE_ID
    assert finding.cwe == UNDETERMINED_PLATFORM_CWE
    assert UNDETERMINED_PLATFORM_SEVERITY == "block"
    assert finding.line_start == 1
    description = finding.description or ""
    assert "could not be determined" in description
    assert "managed_targets.targets" in description
    assert "target_type" in description
    rule_ids = {rule_id for rule_id, _line in _undeclared_findings(content)}
    assert rule_ids == {UNDETERMINED_PLATFORM_RULE_ID}
    assert not any(rule_id.startswith(_PLATFORM_PREFIXES) for rule_id in rule_ids)
