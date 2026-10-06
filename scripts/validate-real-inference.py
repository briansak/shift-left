#!/usr/bin/env python3
"""
Real-model validation for Shift-Left — requires staged weights on disk.

NOT a unit test. Run after:
  ./scripts/download-antares-model.sh
  ./scripts/download-foundation-sec-model.sh

Example:
  SHIFT_LEFT_SKIP_EGRESS_PROBE=1 python scripts/validate-real-inference.py --quant q8_0
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
FSEC = ROOT / "services" / "foundation-sec-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ORCH, FSEC):
    sys.path.insert(0, str(path))

from shift_left_shared.weights import (  # noqa: E402
    VERIFIED_ANTARES_350M,
    VERIFIED_FOUNDATION_SEC_Q4_K_M,
    VERIFIED_FOUNDATION_SEC_Q8_0,
    load_prewarm_manifest,
    verify_antares_weights,
    verify_gguf_weight,
)

# Reuse deterministic fixture strings from unit tests (not unseen corpus).
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


@dataclass
class ValidationReport:
    verified_models: dict[str, Any] = field(default_factory=dict)
    weight_checks: dict[str, str] = field(default_factory=dict)
    fixture_results: list[dict[str, Any]] = field(default_factory=list)
    corpus_results: list[dict[str, Any]] = field(default_factory=list)
    confusion: dict[str, int] = field(default_factory=dict)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    false_negatives: list[dict[str, Any]] = field(default_factory=list)
    determinism: dict[str, Any] = field(default_factory=dict)
    chunking: dict[str, Any] = field(default_factory=dict)
    schema_fit: dict[str, Any] = field(default_factory=dict)
    inference_settings: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _quant_meta(quant: str) -> dict[str, str]:
    if quant == "q4_k_m":
        return VERIFIED_FOUNDATION_SEC_Q4_K_M
    return VERIFIED_FOUNDATION_SEC_Q8_0


def _check_weights(report: ValidationReport, quant: str) -> tuple[Path, Path]:
    manifest = load_prewarm_manifest(ROOT)
    antares_dir = ROOT / VERIFIED_ANTARES_350M["local_path_default"]
    fs_meta = _quant_meta(quant)
    fs_dir = ROOT / fs_meta["local_path_default"]

    try:
        verify_antares_weights(antares_dir, manifest)
        report.weight_checks["antares"] = "ok"
    except Exception as exc:
        report.weight_checks["antares"] = str(exc)
        report.errors.append(f"Antares weights: {exc}")

    try:
        verify_gguf_weight(
            fs_dir,
            manifest,
            manifest_key=fs_meta["manifest_key"],
            verified_meta=fs_meta,
        )
        report.weight_checks["foundation_sec"] = "ok"
    except Exception as exc:
        report.weight_checks["foundation_sec"] = str(exc)
        report.errors.append(f"Foundation-Sec ({quant}): {exc}")

    report.verified_models = {
        "antares": VERIFIED_ANTARES_350M,
        "foundation_sec": fs_meta,
    }
    return antares_dir, fs_dir


def _build_foundation_engine(fs_dir: Path, quant: str):
    from foundation_sec_server.engine import LlamaCppEvalEngine

    meta = _quant_meta(quant)
    manifest_key = meta["manifest_key"]
    os.environ.pop("FOUNDATION_SEC_ENGINE", None)
    return LlamaCppEvalEngine(
        fs_dir,
        gguf_glob=meta["gguf_glob"],
        quant_label="low-memory" if quant == "q4_k_m" else "default",
        load_strategy="on_demand",
        n_ctx=int(os.environ.get("FOUNDATION_SEC_N_CTX", "8192")),
        manifest_key=manifest_key,
    )


def _analyze_file(engine, path: str, content: str) -> list[dict[str, Any]]:
    from foundation_sec_server.analyzer import ConfigAnalyzer

    analyzer = ConfigAnalyzer(engine, max_context_tokens=int(os.environ.get("FOUNDATION_SEC_N_CTX", "8192")))
    lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
    result = analyzer.analyze_files(
        [{"path": path, "hunks": [{"new_start": 1, "new_end": max(lines, 1), "content": content}]}]
    )
    if isinstance(result, dict):
        return list(result.get("findings") or [])
    return result


def _run_fixtures(engine, report: ValidationReport) -> None:
    cases = [
        ("firewall_permissive", "firewall/asa.rules", PERMISSIVE_FIREWALL, True),
        ("firewall_least_privilege", "firewall/asa.rules", LEAST_PRIVILEGE_FIREWALL, False),
        ("terraform_permissive", "infra/main.tf", PERMISSIVE_TERRAFORM, True),
        ("terraform_scoped", "infra/main.tf", SCOPED_TERRAFORM, False),
    ]
    for name, path, content, expect_flagged in cases:
        findings = _analyze_file(engine, path, content)
        flagged = bool(findings)
        report.fixture_results.append(
            {
                "case": name,
                "expect_flagged": expect_flagged,
                "flagged": flagged,
                "match": flagged == expect_flagged,
                "findings": findings,
            }
        )
        if flagged != expect_flagged:
            report.errors.append(
                f"Fixture mismatch {name}: expected flagged={expect_flagged}, got {findings}"
            )


def _handler_path(rel: str) -> str:
    """Map corpus paths to handler-compatible virtual paths."""
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


def _run_corpus(engine, report: ValidationReport) -> None:
    manifest_path = ROOT / "validation" / "corpus" / "manifest.json"
    corpus = json.loads(manifest_path.read_text())
    counts = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}

    for entry in corpus["entries"]:
        rel = entry["path"]
        path = ROOT / "validation" / "corpus" / rel
        content = path.read_text()
        virtual_path = _handler_path(rel)
        findings = _analyze_file(engine, virtual_path, content)
        flagged = bool(findings)
        expect = entry["expect_flagged"]
        result = {
            "id": entry["id"],
            "category": entry["category"],
            "path": rel,
            "expect_flagged": expect,
            "flagged": flagged,
            "findings": findings,
        }
        report.corpus_results.append(result)

        if expect and flagged:
            counts["tp"] += 1
        elif not expect and not flagged:
            counts["tn"] += 1
        elif not expect and flagged:
            counts["fp"] += 1
            report.false_positives.append(result)
        else:
            counts["fn"] += 1
            report.false_negatives.append(result)

    report.confusion = counts


def _run_determinism(engine, report: ValidationReport) -> None:
    sample = (ROOT / "validation" / "corpus" / "bad" / "firewall-any-any.rules").read_text()
    runs: list[list[dict[str, Any]]] = []
    for _ in range(3):
        runs.append(_analyze_file(engine, "firewall/asa.rules", sample))
    normalized = [json.dumps(r, sort_keys=True) for r in runs]
    report.determinism = {
        "runs": 3,
        "identical": normalized[0] == normalized[1] == normalized[2],
        "temperature": 0.1,
        "seed": "llama.cpp default (not explicitly set)",
        "outputs": runs,
    }


def _run_chunking(engine, report: ValidationReport) -> None:
    from foundation_sec_server.analyzer import ConfigAnalyzer
    from foundation_sec_server.chunking import chunk_hunk_content
    from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY

    blocks = []
    for i in range(120):
        blocks.append(
            textwrap.dedent(
                f"""\
                resource "aws_security_group_rule" "rule_{i}" {{
                  type              = "ingress"
                  from_port         = 443
                  to_port           = 443
                  protocol          = "tcp"
                  cidr_blocks       = ["10.{i % 255}.0.0/24"]
                  security_group_id = aws_security_group.app.id
                }}
                """
            )
        )
    content = "\n".join(blocks)
    handler = DEFAULT_REGISTRY.resolve("infra/large.tf")
    token_counter = engine.token_counter() or __import__(
        "foundation_sec_server.chunking", fromlist=["HeuristicTokenCounter"]
    ).HeuristicTokenCounter()
    chunks = chunk_hunk_content(
        content,
        handler=handler,
        line_start=1,
        max_tokens=512,
        token_counter=token_counter,
        overlap_lines=2,
    )
    analyzer = ConfigAnalyzer(engine, max_context_tokens=2048)
    findings = analyzer.analyze_files(
        [
            {
                "path": "infra/large.tf",
                "hunks": [{"new_start": 1, "new_end": content.count("\n") + 1, "content": content}],
            }
        ]
    )
    report.chunking = {
        "chunks_planned": len(chunks),
        "multiple_chunks": len(chunks) > 1,
        "findings_count": len(findings),
        "chunk_line_ranges": [(c.line_start, c.line_end) for c in chunks[:10]],
    }


def _run_schema_fit(engine, report: ValidationReport) -> None:
    from shift_left.config import AppConfig
    from shift_left.foundation_sec.client import FoundationSecClient
    from shift_left.policy.engine import PolicyEngine
    from shift_left.policy.severity import apply_policy_severities, derive_policy_severity

    sample = _analyze_file(engine, "firewall/asa.rules", PERMISSIVE_FIREWALL)
    if not sample:
        report.schema_fit = {"error": "no findings to inspect"}
        return

    raw = sample[0]
    client = FoundationSecClient("http://127.0.0.1:8091")
    finding = client._normalize(raw, "org/repo", "PR-1", "abc")
    config = AppConfig()
    enriched = apply_policy_severities([finding], config)[0]
    policy_engine = PolicyEngine(config.policy)
    evaluation = policy_engine.evaluate(
        repo="org/repo",
        pr_ref="PR-1",
        commit_sha="abc",
        findings=[enriched],
    )
    unclassified = derive_policy_severity(
        finding.model_copy(update={"cwe": "CWE-99999"}),
        config,
    )

    populated = {
        "file_path": bool(finding.file_path),
        "line_range": finding.line_range is not None,
        "cwe": bool(finding.cwe),
        "evidence": bool(finding.evidence),
        "trace": bool(finding.trace),
        "model_asserted_severity": finding.model_asserted_severity.value,
        "policy_severity_mapped": enriched.policy_severity.value if enriched.policy_severity else None,
        "policy_severity_unclassified": unclassified.value,
        "policy_decision": evaluation.pr_decision.pr_decision.value,
    }
    report.schema_fit = {"fields": populated, "sample_finding": finding.model_dump(mode="json")}


def main() -> int:
    parser = argparse.ArgumentParser(description="Real-model validation (requires staged weights)")
    parser.add_argument("--quant", choices=("q8_0", "q4_k_m"), default="q8_0")
    parser.add_argument("--json-out", type=Path, default=ROOT / "validation" / "reports" / "real-inference-report.json")
    parser.add_argument("--skip-corpus", action="store_true")
    parser.add_argument(
        "--fixtures-only",
        action="store_true",
        help="Run fixture cases only (skip corpus, determinism, chunking, schema)",
    )
    parser.add_argument(
        "--corpus-only",
        action="store_true",
        help="Run unseen corpus only (skip fixtures and auxiliary checks)",
    )
    args = parser.parse_args()
    if args.fixtures_only and args.corpus_only:
        parser.error("--fixtures-only and --corpus-only are mutually exclusive")
    if args.corpus_only:
        args.skip_corpus = False

    report = ValidationReport(
        inference_settings={
            "foundation_sec_quant": args.quant,
            "foundation_sec_temperature": 0.1,
            "antares_temperature": 0.0,
            "antares_do_sample": False,
        }
    )

    _check_weights(report, args.quant)
    if report.errors:
        print("Weight verification failed — cannot run real inference:")
        for err in report.errors:
            print(f"  - {err}")
        print("\nSee validation/REAL_MODEL_VALIDATION_REPORT.md §7 for staging steps when online.")
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(asdict(report), indent=2))
        return 1

    fs_dir = ROOT / _quant_meta(args.quant)["local_path_default"]
    engine = _build_foundation_engine(fs_dir, args.quant)

    if args.corpus_only:
        _run_corpus(engine, report)
    elif args.fixtures_only:
        _run_fixtures(engine, report)
    else:
        _run_fixtures(engine, report)
        if not args.skip_corpus:
            _run_corpus(engine, report)
        _run_determinism(engine, report)
        _run_chunking(engine, report)
        _run_schema_fit(engine, report)

    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(asdict(report), indent=2, default=str))

    print(json.dumps({"confusion": report.confusion, "fixture_mismatches": len(report.errors)}, indent=2))
    return 0 if not report.errors else 2


if __name__ == "__main__":
    raise SystemExit(main())
