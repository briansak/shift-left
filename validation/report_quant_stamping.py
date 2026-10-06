"""Shared Q8_0 accuracy-only quant and chat-template fidelity metadata for eval artifacts."""

from __future__ import annotations

from typing import Any

QUANT_EVALUATED = "Q8_0"
QUANT_INTENDED = "Q4_K_M"
ACCURACY_ONLY = True

CHAT_TEMPLATE_FIDELITY_SUMMARY = (
    "raw completion (authoritative); model's own chat_template.jinja available but "
    "produces empty findings on 77/87 files - see chat-truncation-diagnostic.json"
)
AUTHORITATIVE_INFERENCE_PATH = "raw_completion"
HF_CHAT_TEMPLATE_REPO = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct"
HF_CHAT_TEMPLATE_PATH = "chat_template.jinja"
CHAT_TEMPLATE_DIAGNOSTIC = "validation/reports/chat-truncation-diagnostic.json"

STRUCTURED_OUTPUT_FINDING_DOC = "validation/reports/structured-output-finding.md"
STRUCTURED_OUTPUT_CAVEAT_SUMMARY = (
    "CAVEAT: Published platform_specific model TP (best: Q8_0 13/108) was measured with "
    "defective prompt suffix 'JSON array:' (colon -> :// artifact). Correcting the suffix "
    "collapses both quants to 0 TP. All published model numbers require this context. "
    "See validation/reports/structured-output-finding.md."
)
METHODOLOGY_ARTIFACTS = [
    "semantic_threshold (best_fit_v1 min_semantic_fit=0.12)",
    "cwe_overlap_matcher (CWE necessary, not sufficient)",
    "chat_template (raw completion vs chat_template.jinja)",
    "token_budget (n_ctx=4096, usable chunk budget 2176)",
    "prompt_suffix (colon vs bracket vs chat turn)",
]


def quant_fields_from_report(report: dict[str, Any] | None) -> dict[str, Any]:
    """Extract quant fields from a report, falling back to the Q8_0 accuracy-only run."""
    if not report:
        return {
            "quant_evaluated": QUANT_EVALUATED,
            "quant_intended": QUANT_INTENDED,
            "accuracy_only": ACCURACY_ONLY,
        }

    model_config = report.get("model_config") or {}
    server_health = model_config.get("server_health") or {}

    quant_evaluated = (
        report.get("quant_evaluated")
        or model_config.get("quant_evaluated")
        or server_health.get("quant_evaluated")
        or QUANT_EVALUATED
    )
    quant_intended = (
        report.get("quant_intended")
        or model_config.get("quant_intended")
        or model_config.get("required_quant")
        or server_health.get("quant_intended")
        or QUANT_INTENDED
    )
    accuracy_only = report.get("accuracy_only")
    if accuracy_only is None:
        accuracy_only = model_config.get("accuracy_only")
    if accuracy_only is None:
        accuracy_only = server_health.get("accuracy_only")
    if accuracy_only is None:
        accuracy_only = ACCURACY_ONLY

    return {
        "quant_evaluated": quant_evaluated,
        "quant_intended": quant_intended,
        "accuracy_only": accuracy_only,
    }


def structured_output_caveat_fields() -> dict[str, Any]:
    """Canonical structured-output / prompt-suffix caveat for all model eval artifacts."""
    return {
        "structured_output_caveat_summary": STRUCTURED_OUTPUT_CAVEAT_SUMMARY,
        "structured_output_finding_doc": STRUCTURED_OUTPUT_FINDING_DOC,
        "methodology_artifact_count": len(METHODOLOGY_ARTIFACTS),
        "methodology_artifacts": list(METHODOLOGY_ARTIFACTS),
        "structured_output_finding": {
            "caveat_summary": STRUCTURED_OUTPUT_CAVEAT_SUMMARY,
            "finding_doc": STRUCTURED_OUTPUT_FINDING_DOC,
            "best_measured_platform_specific_tp": "13/108",
            "best_measured_quant": "Q8_0",
            "prompt_suffix_at_best_result": "JSON array: (colon; defective)",
            "tp_after_suffix_fix_both_quants": 0,
            "methodology_artifacts": list(METHODOLOGY_ARTIFACTS),
        },
    }


def apply_structured_output_caveat_stamping(report: dict[str, Any]) -> dict[str, Any]:
    """Stamp structured-output caveat on report root, model_config, and server_health."""
    fields = structured_output_caveat_fields()
    report.update(fields)
    model_config = report.setdefault("model_config", {})
    model_config.update(fields)
    server_health = model_config.setdefault("server_health", {})
    server_health.update(fields)
    if isinstance(fields.get("structured_output_finding"), dict):
        server_health["structured_output_finding"] = fields["structured_output_finding"]
    return report


def apply_quant_stamping(report: dict[str, Any]) -> dict[str, Any]:
    """Stamp quant, chat-template fidelity, and structured-output caveat on eval artifacts."""
    report = apply_chat_template_fidelity_stamping(report)
    report = apply_structured_output_caveat_stamping(report)
    fields = quant_fields_from_report(report)
    report.update(fields)
    model_config = report.setdefault("model_config", {})
    model_config.update(fields)
    server_health = model_config.setdefault("server_health", {})
    server_health.update(fields)
    return report


def chat_template_fidelity_fields(
    *,
    source_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Canonical chat-template fidelity stamp for all eval artifacts."""
    summary = CHAT_TEMPLATE_FIDELITY_SUMMARY

    return {
        "chat_template_fidelity_summary": summary,
        "inference_path": AUTHORITATIVE_INFERENCE_PATH,
        "llama_cpp_chat_format": "raw_completion",
        "gguf_embedded_chat_template": False,
        "uses_model_specific_jinja_template": False,
        "chat_template_evaluated_and_rejected": True,
        "chat_template_diagnostic": CHAT_TEMPLATE_DIAGNOSTIC,
        "hf_chat_template_repo": HF_CHAT_TEMPLATE_REPO,
        "hf_chat_template_path": HF_CHAT_TEMPLATE_PATH,
        "chat_template_fidelity": {
            "fidelity_summary": summary,
            "inference_path": AUTHORITATIVE_INFERENCE_PATH,
            "llama_cpp_chat_format": "raw_completion",
            "gguf_embedded_chat_template": False,
            "uses_model_specific_jinja_template": False,
            "chat_template_evaluated_and_rejected": True,
            "chat_template_diagnostic": CHAT_TEMPLATE_DIAGNOSTIC,
            "hf_chat_template_repo": HF_CHAT_TEMPLATE_REPO,
            "hf_chat_template_path": HF_CHAT_TEMPLATE_PATH,
        },
    }


def apply_chat_template_fidelity_stamping(report: dict[str, Any]) -> dict[str, Any]:
    """Stamp chat-template fidelity on report root, model_config, and server_health."""
    fields = chat_template_fidelity_fields(source_report=report)
    report.update(fields)
    model_config = report.setdefault("model_config", {})
    model_config.update(fields)
    server_health = model_config.setdefault("server_health", {})
    server_health.update(fields)
    if isinstance(fields.get("chat_template_fidelity"), dict):
        server_health["chat_template_fidelity"] = fields["chat_template_fidelity"]
    return report


def merge_quant_metadata(
    metadata: dict[str, Any],
    *,
    source_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Merge quant and chat-template fidelity fields into a sidecar/manifest dict."""
    source = source_report or metadata
    return {
        **metadata,
        **quant_fields_from_report(source),
        **chat_template_fidelity_fields(source_report=source),
        **structured_output_caveat_fields(),
    }
