"""Foundation-Sec config/IaC evaluation orchestration."""

from __future__ import annotations

import logging
import os
import time
from typing import Any

from foundation_sec_server.chunking import (
    HeuristicTokenCounter,
    chunk_hunk_content,
    compute_usable_token_budget,
    merge_findings,
)
from foundation_sec_server.engine import EvalEngine
from foundation_sec_server.findings_policy import MODEL_SERVER_HANDLER_ASSERTED_CWE
from shift_left.ui.cwe_dictionary import apply_model_asserted_cwe_fields
from foundation_sec_server.handlers.types import HandlerCweMatch
from foundation_sec_server.handlers.cwe_rules import (
    attach_handler_cwe,
    match_handler_cwes,
)
from foundation_sec_server.handlers.registry import DEFAULT_REGISTRY
from foundation_sec_server.workflow_guards import should_skip_ci_workflow

logger = logging.getLogger(__name__)

OUTCOME_COMPLETED_NO_FINDINGS = "completed_no_findings"
OUTCOME_COMPLETED_WITH_FINDINGS = "completed_with_findings"
OUTCOME_FAILED = "failed"


class ConfigAnalyzer:
    def __init__(
        self,
        engine: EvalEngine,
        *,
        max_context_tokens: int = 8192,
        chunk_overlap_lines: int = 2,
        prompt_scaffold_tokens: int | None = None,
        max_output_tokens: int | None = None,
        safety_margin: int | None = None,
    ) -> None:
        self._engine = engine
        self._max_context_tokens = max_context_tokens
        self._chunk_overlap_lines = chunk_overlap_lines
        self._prompt_scaffold_tokens = prompt_scaffold_tokens or int(
            os.environ.get("FOUNDATION_SEC_PROMPT_SCAFFOLD_TOKENS", "768")
        )
        self._max_output_tokens = max_output_tokens or int(
            os.environ.get("FOUNDATION_SEC_MAX_OUTPUT_TOKENS", "1024")
        )
        self._safety_margin = safety_margin or int(
            os.environ.get("FOUNDATION_SEC_SAFETY_MARGIN_TOKENS", "128")
        )
        self._registry = DEFAULT_REGISTRY
        self._usable_token_budget = compute_usable_token_budget(
            n_ctx=self._max_context_tokens,
            prompt_scaffold_tokens=self._prompt_scaffold_tokens,
            max_output_tokens=self._max_output_tokens,
            safety_margin=self._safety_margin,
        )

    def analyze_files(
        self,
        files: list[dict[str, Any]],
        *,
        prompt_variant: str = "baseline",
        skip_inference: bool = False,
    ) -> dict[str, Any]:
        started = time.monotonic()
        timings: dict[str, int] = {"handler_ms": 0, "model_load_ms": 0, "inference_ms": 0}
        self._engine.reset_stage_timings()
        completion_tokens = 0
        token_counter = self._engine.token_counter() or HeuristicTokenCounter()
        all_findings: list[dict] = []

        try:
            for file_entry in files:
                path = file_entry["path"]
                target_type = file_entry.get("target_type")
                if should_skip_ci_workflow(path, ""):
                    continue
                handler = self._registry.resolve(path)
                for hunk in file_entry.get("hunks", []):
                    hunk_content = hunk.get("content", "")
                    if should_skip_ci_workflow(path, hunk_content):
                        continue
                    content = hunk.get("content", "")
                    line_start = int(hunk.get("new_start", 1))
                    chunks = chunk_hunk_content(
                        content,
                        handler=handler,
                        line_start=line_start,
                        max_tokens=self._usable_token_budget,
                        token_counter=token_counter,
                        overlap_lines=self._chunk_overlap_lines,
                    )
                    for chunk in chunks:
                        try:
                            chunk_findings: list[dict[str, Any]] = []
                            if not skip_inference:
                                chunk_findings = self._engine.evaluate_chunk(
                                    file_path=path,
                                    handler=handler,
                                    chunk_content=chunk.content,
                                    line_start=chunk.line_start,
                                    line_end=chunk.line_end,
                                    prompt_variant=prompt_variant,
                                    target_type=target_type,
                                )
                                for key, value in self._engine.consume_stage_timings_ms().items():
                                    timings[key] = timings.get(key, 0) + value
                                completion_tokens += self._engine.consume_completion_tokens()
                        except Exception as exc:  # noqa: BLE001
                            logger.exception(
                                "Chunk inference failed for %s (lines %s-%s)",
                                path,
                                chunk.line_start,
                                chunk.line_end,
                            )
                            timings["total"] = int((time.monotonic() - started) * 1000)
                            return {
                                "outcome": OUTCOME_FAILED,
                                "findings": [],
                                "failure_class": "chunk_error",
                                "failure_stage": "chunk",
                                "failure_message": (
                                    f"Chunk evaluation failed for {path} "
                                    f"(lines {chunk.line_start}-{chunk.line_end}): {exc}"
                                ),
                                "timings_ms": timings,
                                "usage": {"completion_tokens": completion_tokens},
                            }
                        try:
                            handler_started = time.monotonic()
                            handler_matches = match_handler_cwes(
                                chunk_content=chunk.content,
                                handler=handler,
                                line_offset=chunk.line_start - 1,
                            )
                            timings["handler_ms"] += int((time.monotonic() - handler_started) * 1000)
                            covered_handler_ids: set[str] = set()
                            for finding in chunk_findings:
                                finding.setdefault("handler", handler.name)
                                if finding.get("cwe") and not finding.get("model_asserted_cwe"):
                                    model_cwe, recognized = apply_model_asserted_cwe_fields(
                                        model_asserted_cwe=None,
                                        legacy_cwe=finding["cwe"],
                                    )
                                    finding["model_asserted_cwe"] = model_cwe
                                    finding["model_cwe_recognized"] = recognized
                                best_match = _best_handler_match_for_finding(
                                    finding,
                                    handler_matches,
                                )
                                attach_handler_cwe(finding, best_match)
                                if best_match is not None:
                                    covered_handler_ids.add(best_match.pattern_id)
                                if chunk.chunk_index > 0:
                                    trace = finding.get("trace") or ""
                                    finding["trace"] = f"{trace} | chunk={chunk.chunk_index}".strip()
                            all_findings.extend(chunk_findings)
                            for handler_match in handler_matches:
                                if handler_match.pattern_id in covered_handler_ids:
                                    continue
                                if handler_match.evaluation_status != "matched":
                                    all_findings.append(
                                        _synthesize_handler_finding(
                                            path=path,
                                            handler_name=handler.name,
                                            chunk=chunk,
                                            handler_match=handler_match,
                                        )
                                    )
                                    continue
                                if not _handler_match_covered_by_model(
                                    handler_match,
                                    chunk_findings,
                                ):
                                    all_findings.append(
                                        _synthesize_handler_finding(
                                            path=path,
                                            handler_name=handler.name,
                                            chunk=chunk,
                                            handler_match=handler_match,
                                        )
                                    )
                        except Exception as exc:  # noqa: BLE001
                            logger.exception(
                                "Post-inference handler matching failed for %s (lines %s-%s)",
                                path,
                                chunk.line_start,
                                chunk.line_end,
                            )
                            timings["total"] = int((time.monotonic() - started) * 1000)
                            return {
                                "outcome": OUTCOME_FAILED,
                                "findings": [],
                                "failure_class": "handler_error",
                                "failure_stage": "handler_match",
                                "failure_message": (
                                    f"Handler matching failed for {path} "
                                    f"(lines {chunk.line_start}-{chunk.line_end}): {exc}"
                                ),
                                "timings_ms": timings,
                                "usage": {"completion_tokens": completion_tokens},
                            }
        except Exception as exc:  # noqa: BLE001
            logger.exception("Foundation-Sec analysis failed before handler matching completed")
            timings["total"] = int((time.monotonic() - started) * 1000)
            return {
                "outcome": OUTCOME_FAILED,
                "findings": [],
                "failure_class": "inference_error",
                "failure_stage": "generation",
                "failure_message": str(exc),
                "timings_ms": timings,
                "usage": {"completion_tokens": completion_tokens},
            }

        merged = merge_findings(all_findings)
        timings["total"] = int((time.monotonic() - started) * 1000)
        outcome = (
            OUTCOME_COMPLETED_WITH_FINDINGS if merged else OUTCOME_COMPLETED_NO_FINDINGS
        )
        return {
            "outcome": outcome,
            "findings": merged,
            "failure_class": None,
            "failure_stage": None,
            "failure_message": None,
            "timings_ms": timings,
            "usage": {"completion_tokens": completion_tokens},
        }

    def status(self) -> dict[str, Any]:
        base = self._engine.status()
        base["chunk_budget"] = {
            "n_ctx": self._max_context_tokens,
            "prompt_scaffold_tokens": self._prompt_scaffold_tokens,
            "max_output_tokens": self._max_output_tokens,
            "safety_margin": self._safety_margin,
            "usable": self._usable_token_budget,
        }
        return base

    def unload(self) -> None:
        self._engine.unload()


def _line_overlaps(
    finding: dict,
    *,
    line_start: int,
    line_end: int,
) -> bool:
    f_start = int(finding.get("line_start") or finding.get("line_range", {}).get("start") or 0)
    f_end = int(finding.get("line_end") or finding.get("line_range", {}).get("end") or f_start)
    if f_start <= 0:
        return True
    return not (f_end < line_start or f_start > line_end)


def _best_handler_match_for_finding(
    finding: dict,
    handler_matches: list[HandlerCweMatch],
) -> HandlerCweMatch | None:
    matched: list[HandlerCweMatch] = []
    for handler_match in handler_matches:
        if handler_match.line_start is None or handler_match.line_end is None:
            matched.append(handler_match)
            continue
        if _line_overlaps(
            finding,
            line_start=handler_match.line_start,
            line_end=handler_match.line_end,
        ):
            matched.append(handler_match)
    for handler_match in matched:
        if handler_match.evaluation_status == "matched":
            return handler_match
    return matched[0] if matched else None


def _handler_match_covered_by_model(
    handler_match: HandlerCweMatch,
    chunk_findings: list[dict],
) -> bool:
    if handler_match.line_start is None or handler_match.line_end is None:
        return bool(chunk_findings)
    return any(
        _line_overlaps(
            finding,
            line_start=handler_match.line_start,
            line_end=handler_match.line_end,
        )
        for finding in chunk_findings
    )


def _synthesize_handler_finding(
    *,
    path: str,
    handler_name: str,
    chunk,
    handler_match: HandlerCweMatch,
) -> dict:
    line_start = handler_match.line_start or chunk.line_start
    line_end = handler_match.line_end or chunk.line_end
    is_unevaluated = handler_match.evaluation_status == "unevaluated"
    return {
        "file_path": path,
        "line_start": line_start,
        "line_end": line_end,
        "handler_asserted_cwe": MODEL_SERVER_HANDLER_ASSERTED_CWE,
        "model_asserted_cwe": None,
        "severity": "high" if not is_unevaluated else "medium",
        "confidence": 1.0 if not is_unevaluated else 0.5,
        "title": handler_match.title or f"Deterministic rule: {handler_match.pattern_id}",
        "description": handler_match.description or handler_match.pattern_id,
        "evidence": f"lines {line_start}-{line_end}",
        "trace": (
            f"handler:unevaluated/{handler_match.pattern_id}"
            if is_unevaluated
            else f"handler:{handler_match.pattern_id}"
        ),
        "handler": handler_name,
        "deterministic_only": True,
    }
