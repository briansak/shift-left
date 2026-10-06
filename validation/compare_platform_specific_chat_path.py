#!/usr/bin/env python3
"""Three-way platform_specific comparability: raw vs wrong llama-3 vs correct template."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ORCH = ROOT / "services" / "orchestrator"
SHARED = ROOT / "services" / "shift-left-shared"
FSEC = ROOT / "services" / "foundation-sec-server"
VALIDATION = ROOT / "validation"
for path in (SHARED, ORCH, FSEC, VALIDATION):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from foundation_sec_server.chat_inference import (  # noqa: E402
    DEFAULT_SYSTEM_PROMPT,
    verify_chat_template_render,
)
from model_eval_matching import MATCHER_BEST_FIT  # noqa: E402
from report_quant_stamping import merge_quant_metadata  # noqa: E402
from rescore_model_reports import _infer_findings, _load_findings_cache  # noqa: E402
from retro_constrained_validation import retro_validate_cache  # noqa: E402

REPORTS = ROOT / "validation" / "reports"
FINDINGS_CACHE = REPORTS / "findings-cache"
RAW_CACHE = FINDINGS_CACHE / "platform_specific.findings.json"
WRONG_LLAMA3_CACHE = FINDINGS_CACHE / "platform_specific.chat_inference.findings.json"
CORRECT_TEMPLATE_CACHE = FINDINGS_CACHE / "platform_specific.foundation_sec_template.findings.json"
OUTPUT_JSON = REPORTS / "platform-specific-chat-path-comparison.json"
OUTPUT_TXT = REPORTS / "platform-specific-chat-path-comparison.txt"

RAW_BASELINE_TP = 13
WITHIN_TP_TOLERANCE = 2
VERIFY_USER_PROMPT = (
    "You are a security auditor reviewing a configuration file. "
    "List one misconfiguration, severity, and recommended fix."
)


def _aggregate_from_rescore(rescore: dict[str, Any]) -> dict[str, int]:
    agg = rescore["summary"]["aggregate_model"]
    return {
        "true_positives": int(agg["true_positives"]),
        "false_positives": int(agg["false_positives"]),
        "false_negatives": int(agg["false_negatives"]),
    }


def _fabrication_inline(evidence_not_substring: int, emitted: int) -> str:
    return f"{evidence_not_substring}/{emitted}"


def _metrics_from_retro(retro: dict[str, Any]) -> dict[str, Any]:
    summary = retro.get("summary") or {}
    emitted = int(summary.get("model_findings_emitted") or 0)
    evidence_not_substring = int(summary.get("evidence_not_substring_count") or 0)
    grounded = max(emitted - evidence_not_substring, 0)
    return {
        "emitted": emitted,
        "surviving": int(summary.get("model_findings_surviving") or 0),
        "evidence_not_substring": evidence_not_substring,
        "grounded_evidence": grounded,
        "fabrication_inline": _fabrication_inline(evidence_not_substring, emitted),
        "grounding_inline": f"{grounded}/{emitted}",
    }


def _score_cache(records: list[dict[str, Any]], *, label: str) -> dict[str, Any]:
    from rescore_model_reports import rescore_findings

    corrected = rescore_findings(records, matcher=MATCHER_BEST_FIT)
    retro = retro_validate_cache(records, prompt_variant=label)
    return {
        "label": label,
        "rule_level": _aggregate_from_rescore(corrected),
        "fabrication": _metrics_from_retro(retro),
        "files_in_cache": len(records),
    }


def _path_line(path: dict[str, Any]) -> str:
    rl = path["rule_level"]
    fab = path["fabrication"]
    return (
        f"  TP/FP/FN: {rl['true_positives']}/{rl['false_positives']}/{rl['false_negatives']}\n"
        f"  Ungrounded/emitted: {fab['fabrication_inline']}\n"
        f"  Grounded/emitted: {fab['grounding_inline']}"
    )


def _format_text(report: dict[str, Any]) -> str:
    raw = report["raw_completion_baseline"]
    wrong = report["wrong_llama3_chat_path"]
    correct = report["correct_template_chat_path"]
    verdict = report["comparability_verdict"]
    verify = report["template_render_verification"]
    decision = report["production_decision"]
    lines = [
        "=== platform_specific: three-way chat-template comparability ===",
        (
            f"quant_evaluated={report.get('quant_evaluated')} "
            f"chat_template_fidelity_summary={report.get('chat_template_fidelity_summary')}"
        ),
        "",
        f"Authoritative inference path: {decision['authoritative_path']}",
        f"Published results table: {decision['published_table_status']}",
        f"Chat path decision: {decision['chat_path_status']}",
        f"  {decision['chat_path_reason']}",
        "",
        f"Template render verification (byte-identical): {verify['identical']}",
        f"  template: {verify['template_path']}",
        "",
        "Raw-completion baseline (authoritative; unchanged published table):",
        _path_line(raw),
        "",
        "Wrong llama-3 chat_format path (evaluated, rejected):",
        _path_line(wrong) if wrong else "  (cache missing)",
        "",
        "Correct Foundation-Sec chat_template.jinja path (evaluated, rejected):",
        _path_line(correct),
        "",
        f"Delta TP (correct - raw): {report['delta_tp_correct_vs_raw']:+d}",
        f"Delta TP (correct - wrong llama-3): {report['delta_tp_correct_vs_wrong_llama3']:+d}",
        f"Comparability check: {verdict['status']}",
        f"  {verdict['detail']}",
        f"See also: {decision['finding_doc']}",
    ]
    return "\n".join(lines) + "\n"


def _comparability_verdict(delta_tp: int) -> dict[str, Any]:
    within_tolerance = abs(delta_tp) <= WITHIN_TP_TOLERANCE
    if within_tolerance:
        return {
            "status": "comparable",
            "detail": (
                f"Chat-template TP moved by {delta_tp:+d} vs raw (within ±{WITHIN_TP_TOLERANCE}). "
                "Raw completion remains authoritative; published table unchanged."
            ),
            "table_rerun_required": False,
        }
    return {
        "status": "chat_path_rejected",
        "detail": (
            f"Chat-template TP moved by {delta_tp:+d} vs raw (outside ±{WITHIN_TP_TOLERANCE}). "
            "Raw completion remains authoritative; published table not re-run."
        ),
        "table_rerun_required": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-quant-mismatch", action="store_true")
    parser.add_argument("--skip-inference", action="store_true")
    args = parser.parse_args()

    verify = verify_chat_template_render(
        VERIFY_USER_PROMPT,
        system_prompt=DEFAULT_SYSTEM_PROMPT,
    )
    print("=== chat template render verification ===")
    print(f"template: {verify['template_path']}")
    print(f"byte-identical: {verify['identical']}")
    print("--- rendered prompt ---")
    print(verify["handler_render"])
    if not verify["identical"]:
        print("ERROR: handler render does not match template file render", file=sys.stderr)
        return 1

    raw_records = _load_findings_cache(RAW_CACHE)
    if raw_records is None:
        print(f"ERROR: missing raw cache {RAW_CACHE}", file=sys.stderr)
        return 1

    wrong_records = _load_findings_cache(WRONG_LLAMA3_CACHE)
    if wrong_records is None:
        print(
            f"WARNING: missing wrong-llama-3 cache {WRONG_LLAMA3_CACHE}; "
            "three-way comparison will omit historical llama-3 path.",
            file=sys.stderr,
        )

    if not args.skip_inference:
        print(
            "Inferring platform_specific via corrected Foundation-Sec chat template ...",
            flush=True,
        )
        correct_records = _infer_findings(
            "platform_specific",
            allow_quant_mismatch=args.allow_quant_mismatch,
        )
        CORRECT_TEMPLATE_CACHE.parent.mkdir(parents=True, exist_ok=True)
        CORRECT_TEMPLATE_CACHE.write_text(
            json.dumps(
                {
                    "prompt_variant": "platform_specific",
                    "inference_path": "foundation_sec_chat_template_jinja",
                    "generated_at": datetime.now(UTC).isoformat(),
                    "files": correct_records,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"Wrote {CORRECT_TEMPLATE_CACHE.relative_to(ROOT)}", flush=True)
    else:
        correct_records = _load_findings_cache(CORRECT_TEMPLATE_CACHE)
        if correct_records is None:
            print(
                f"ERROR: missing correct-template cache {CORRECT_TEMPLATE_CACHE}; "
                "run without --skip-inference",
                file=sys.stderr,
            )
            return 1

    raw_scored = _score_cache(raw_records, label="platform_specific_raw_completion")
    wrong_scored = (
        _score_cache(wrong_records, label="platform_specific_wrong_llama3")
        if wrong_records is not None
        else None
    )
    correct_scored = _score_cache(
        correct_records,
        label="platform_specific_foundation_sec_template",
    )

    delta_tp_correct_vs_raw = (
        correct_scored["rule_level"]["true_positives"] - raw_scored["rule_level"]["true_positives"]
    )
    delta_tp_correct_vs_wrong = None
    if wrong_scored is not None:
        delta_tp_correct_vs_wrong = (
            correct_scored["rule_level"]["true_positives"]
            - wrong_scored["rule_level"]["true_positives"]
        )

    report = merge_quant_metadata(
        {
            "generated_at": datetime.now(UTC).isoformat(),
            "task": "platform_specific_three_way_chat_comparability",
            "matcher": MATCHER_BEST_FIT,
            "inference_paths": {
                "raw": "llama_cpp raw completion (historical cache)",
                "wrong_llama3": "chat_format=llama-3 (historical cache)",
                "correct_template": (
                    "models/foundation-sec-chat-template.jinja via Jinja2ChatFormatter"
                ),
            },
            "raw_cache": str(RAW_CACHE.relative_to(ROOT)),
            "wrong_llama3_cache": str(WRONG_LLAMA3_CACHE.relative_to(ROOT)),
            "correct_template_cache": str(CORRECT_TEMPLATE_CACHE.relative_to(ROOT)),
            "template_render_verification": {
                "identical": verify["identical"],
                "template_path": verify["template_path"],
                "system_prompt": DEFAULT_SYSTEM_PROMPT,
                "user_prompt": VERIFY_USER_PROMPT,
                "rendered_prompt": verify["handler_render"],
            },
            "raw_completion_baseline": raw_scored,
            "wrong_llama3_chat_path": wrong_scored,
            "correct_template_chat_path": correct_scored,
            "published_table_baseline_tp": RAW_BASELINE_TP,
            "delta_tp_correct_vs_raw": delta_tp_correct_vs_raw,
            "delta_tp_correct_vs_wrong_llama3": delta_tp_correct_vs_wrong,
            "tp_tolerance": WITHIN_TP_TOLERANCE,
            "comparability_verdict": _comparability_verdict(delta_tp_correct_vs_raw),
            "production_decision": {
                "authoritative_path": "raw_completion",
                "published_table_status": "unchanged — all published structured-variant numbers measured on raw completion",
                "chat_path_status": "evaluated and rejected",
                "chat_path_reason": (
                    "Correct chat_template.jinja yields 5/108 TP vs 13/108 on raw completion; "
                    "77/87 labeled files return a 1-token [] (under-detection, not truncation). "
                    "Wrong llama-3 handler yields 0 findings. See chat-template-finding.md."
                ),
                "finding_doc": "validation/reports/chat-template-finding.md",
                "truncation_diagnostic": "validation/reports/chat-truncation-diagnostic.json",
            },
        }
    )

    OUTPUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    OUTPUT_TXT.write_text(_format_text(report), encoding="utf-8")
    print(_format_text(report))
    print(f"Wrote {OUTPUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
