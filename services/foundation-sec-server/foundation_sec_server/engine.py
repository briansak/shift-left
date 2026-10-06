"""Foundation-Sec inference engines — llama.cpp GGUF (production) and scripted (tests)."""

from __future__ import annotations

import gc
import json
import logging
import os
import platform
import re
import threading
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from foundation_sec_server.chat_inference import (
    AUTHORITATIVE_INFERENCE_PATH,
    build_foundation_sec_chat_handler,
    chat_template_fidelity,
    run_advisory_completion_with_usage,
    use_chat_template,
)
from foundation_sec_server.gguf_paths import (
    gguf_settings_from_env,
    load_prewarm_manifest,
    resolve_gguf_path,
    verify_gguf_against_manifest,
)
from foundation_sec_server.model_profiles import (
    MODEL_VARIANT_REASONING,
    REASONING_MAX_TOKENS_DEFAULT,
    REASONING_N_CTX_DEFAULT,
    REASONING_SPLIT_END,
    REASONING_SPLIT_START,
)
from foundation_sec_server.handlers.registry import ConfigFormatHandler
from foundation_sec_server.preprocess import strip_inactive_lines
from foundation_sec_server.prompts import (
    PLATFORM_SPECIFIC_SUFFIX_BRACKET,
    PLATFORM_SPECIFIC_SUFFIX_COLON,
    PROMPT_VARIANT_CONSTRAINED_OUTPUT,
    PROMPT_VARIANT_PLATFORM_CONSTRAINED,
    PROMPT_VARIANT_PLATFORM_SPECIFIC,
    PROMPT_VARIANT_PLATFORM_SPECIFIC_COLON,
    build_constrained_output_prompt,
    build_platform_constrained_prompt,
    build_platform_specific_prompt,
)

logger = logging.getLogger(__name__)

_EVAL_PROMPT = """You are Foundation-Sec, performing DEFENSIVE review of a PROPOSED configuration change.
You evaluate supplied config text ONLY — you do NOT scan or probe live infrastructure.

{format_context}

Return ONLY a JSON array (no markdown). Each object:
  file_path, line_start, line_end, cwe, cve_refs (array), severity (info|low|medium|high|critical),
  confidence (0.0-1.0), title, description, evidence, trace

If uncertain, use lower confidence (0.3-0.6) but still include likely concerns for human review.
If no concerns, return [].

File: {file_path}
Lines: {line_start}-{line_end}
```config
{content}
```
JSON array:"""


class EvalEngine(ABC):
    @abstractmethod
    def evaluate_chunk(
        self,
        *,
        file_path: str,
        handler: ConfigFormatHandler,
        chunk_content: str,
        line_start: int,
        line_end: int,
        prompt_variant: str = "baseline",
        target_type: str | None = None,
    ) -> list[dict[str, Any]]: ...

    @abstractmethod
    def unload(self) -> None: ...

    @abstractmethod
    def status(self) -> dict[str, Any]: ...

    def token_counter(self) -> Any | None:
        """Return a TokenCounter when llama.cpp is loaded; None for scripted mode."""
        return None

    def reset_stage_timings(self) -> None:
        return None

    def consume_stage_timings_ms(self) -> dict[str, int]:
        return {}

    def consume_completion_tokens(self) -> int:
        return 0


class LlamaCppEvalEngine(EvalEngine):
    """Foundation-Sec via llama.cpp GGUF — local weights only."""

    def __init__(
        self,
        model_dir: Path,
        *,
        gguf_glob: str,
        quant_label: str,
        load_strategy: str = "on_demand",
        n_ctx: int = 8192,
        manifest_key: str = "foundation-sec",
        model_variant: str = "instruct",
        max_output_tokens: int | None = None,
    ) -> None:
        self._model_dir = model_dir
        self._gguf_glob = gguf_glob
        self._quant_label = quant_label
        self._load_strategy = load_strategy
        self._n_ctx = n_ctx
        self._manifest_key = manifest_key
        self._model_variant = model_variant
        self._max_output_tokens = max_output_tokens or (
            REASONING_MAX_TOKENS_DEFAULT
            if model_variant == MODEL_VARIANT_REASONING
            else 1024
        )
        self._gguf_path: Path | None = None
        self._llm: Any | None = None
        self._lock = threading.Lock()
        self._stage_timings_ms: dict[str, int] = {
            "model_load_ms": 0,
            "inference_ms": 0,
        }
        self._stage_completion_tokens = 0
        self._resolve_and_verify_gguf()

    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[3]

    def _resolve_and_verify_gguf(self) -> None:
        gguf = resolve_gguf_path(
            self._model_dir,
            gguf_glob=self._gguf_glob,
            quant_label=self._quant_label,
            model_variant=self._model_variant,
        )
        manifest = load_prewarm_manifest(self._repo_root())
        verify_gguf_against_manifest(gguf, manifest, key=self._manifest_key)
        self._gguf_path = gguf

    def reset_stage_timings(self) -> None:
        self._stage_timings_ms = {"model_load_ms": 0, "inference_ms": 0}
        self._stage_completion_tokens = 0

    def consume_stage_timings_ms(self) -> dict[str, int]:
        timings = dict(self._stage_timings_ms)
        self._stage_timings_ms = {"model_load_ms": 0, "inference_ms": 0}
        return timings

    def consume_completion_tokens(self) -> int:
        tokens = self._stage_completion_tokens
        self._stage_completion_tokens = 0
        return tokens

    def load(self) -> None:
        with self._lock:
            if self._llm is not None:
                return
            load_started = time.monotonic()
            assert self._gguf_path is not None
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            from llama_cpp import Llama

            n_gpu_layers = 0
            if platform.system() == "Darwin":
                n_gpu_layers = -1
            elif os.environ.get("FOUNDATION_SEC_CUDA", "").lower() in {"1", "true"}:
                n_gpu_layers = -1

            logger.info(
                "Loading Foundation-Sec GGUF %s (n_ctx=%s, quant=%s)",
                self._gguf_path.name,
                self._n_ctx,
                self._quant_label,
            )
            llama_kwargs: dict[str, Any] = {
                "model_path": str(self._gguf_path),
                "n_ctx": self._n_ctx,
                "n_gpu_layers": n_gpu_layers,
                "verbose": False,
            }
            if use_chat_template():
                llama_kwargs["chat_handler"] = build_foundation_sec_chat_handler()
            self._llm = Llama(**llama_kwargs)
            self._assert_context_within_model_support()
            self._stage_timings_ms["model_load_ms"] += int(
                (time.monotonic() - load_started) * 1000
            )

    def _assert_context_within_model_support(self) -> None:
        assert self._llm is not None
        train_ctx = getattr(self._llm, "n_ctx_train", None)
        if callable(train_ctx):
            supported = int(train_ctx())
            if self._n_ctx > supported:
                raise ValueError(
                    f"FOUNDATION_SEC_N_CTX={self._n_ctx} exceeds model training context "
                    f"({supported}). Reduce n_ctx in config."
                )

    def unload(self) -> None:
        with self._lock:
            if self._llm is None:
                return
            del self._llm
            self._llm = None
            gc.collect()
            logger.info("Foundation-Sec model unloaded")

    def token_counter(self) -> Any | None:
        if self._llm is None:
            return None
        from foundation_sec_server.chunking import LlamaTokenCounter

        return LlamaTokenCounter(self._llm)

    def status(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "engine": "llama.cpp",
            "quant": self._quant_label,
            "model_variant": self._model_variant,
            "gguf_glob": self._gguf_glob,
            "gguf_file": self._gguf_path.name if self._gguf_path else None,
            "loaded": self._llm is not None,
            "load_strategy": self._load_strategy,
            "model_dir": str(self._model_dir),
            "n_ctx": self._n_ctx,
            "max_output_tokens": self._max_output_tokens,
            "platform": platform.platform(),
            "inference_path": (
                "reasoning_chat_template"
                if self._model_variant == MODEL_VARIANT_REASONING
                else ("chat_template" if use_chat_template() else AUTHORITATIVE_INFERENCE_PATH)
            ),
            "reasoning_split_delimiter": (
                f"{REASONING_SPLIT_START}...{REASONING_SPLIT_END}"
                if self._model_variant == MODEL_VARIANT_REASONING
                else None
            ),
        }
        if self._llm is not None:
            payload["chat_template_fidelity"] = chat_template_fidelity(self._llm)
        return payload

    def evaluate_chunk(
        self,
        *,
        file_path: str,
        handler: ConfigFormatHandler,
        chunk_content: str,
        line_start: int,
        line_end: int,
        prompt_variant: str = "baseline",
        target_type: str | None = None,
    ) -> list[dict[str, Any]]:
        if self._load_strategy == "on_demand":
            self.load()
        elif self._llm is None:
            self.load()

        active_content, stripped = strip_inactive_lines(chunk_content, handler)
        if prompt_variant in {
            PROMPT_VARIANT_PLATFORM_SPECIFIC,
            PROMPT_VARIANT_PLATFORM_SPECIFIC_COLON,
        }:
            prompt = build_platform_specific_prompt(
                handler=handler,
                target_type=target_type,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                content=active_content,
                suffix=(
                    PLATFORM_SPECIFIC_SUFFIX_COLON
                    if prompt_variant == PROMPT_VARIANT_PLATFORM_SPECIFIC_COLON
                    else PLATFORM_SPECIFIC_SUFFIX_BRACKET
                ),
            )
        elif prompt_variant == PROMPT_VARIANT_CONSTRAINED_OUTPUT:
            prompt = build_constrained_output_prompt(
                handler=handler,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                content=active_content,
            )
        elif prompt_variant == PROMPT_VARIANT_PLATFORM_CONSTRAINED:
            prompt = build_platform_constrained_prompt(
                handler=handler,
                target_type=target_type,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                content=active_content,
            )
        else:
            prompt = _EVAL_PROMPT.format(
                format_context=handler.prompt_context,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                content=active_content[:12000],
            )
        assert self._llm is not None
        infer_started = time.monotonic()
        if self._model_variant == MODEL_VARIANT_REASONING:
            from foundation_sec_server.reasoning_inference import ReasoningModelClient

            completion = ReasoningModelClient(
                self._llm,
                model_dir=self._model_dir,
                max_tokens=self._max_output_tokens,
            ).complete(prompt)
            text = completion.answer
            self._stage_completion_tokens += int(completion.completion_token_count or 0)
        else:
            text, tokens = run_advisory_completion_with_usage(
                self._llm,
                prompt,
                max_tokens=self._max_output_tokens,
                temperature=0.1,
                stop=["```"],
            )
            self._stage_completion_tokens += tokens
        self._stage_timings_ms["inference_ms"] += int(
            (time.monotonic() - infer_started) * 1000
        )
        findings = _parse_json_findings(
            text,
            file_path,
            prepend_array_bracket=prompt_variant == PROMPT_VARIANT_PLATFORM_SPECIFIC,
        )
        if self._load_strategy == "on_demand":
            self.unload()
        return findings


class ScriptedEvalEngine(EvalEngine):
    """Deterministic engine for tests — firewall any/any vs least-privilege."""

    def unload(self) -> None:
        return None

    def status(self) -> dict[str, Any]:
        return {"engine": "scripted", "loaded": True}

    def evaluate_chunk(
        self,
        *,
        file_path: str,
        handler: ConfigFormatHandler,
        chunk_content: str,
        line_start: int,
        line_end: int,
        prompt_variant: str = "baseline",
        target_type: str | None = None,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        text = chunk_content.lower()

        if _matches_permissive_firewall(text):
            findings.append(
                {
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "model_asserted_cwe": "CWE-284",
                    "cwe": "CWE-284",
                    "cve_refs": [],
                    "severity": "high",
                    "confidence": 0.92,
                    "title": "Overly permissive firewall rule (any/any ALLOW)",
                    "description": (
                        "Proposed configuration appears to allow unrestricted traffic. "
                        "Review for least-privilege alternatives."
                    ),
                    "evidence": chunk_content[:400],
                    "trace": "scripted: permissive firewall pattern",
                }
            )

        if "0.0.0.0/0" in chunk_content and "allow" in text:
            if not findings:
                findings.append(
                    {
                        "file_path": file_path,
                        "line_start": line_start,
                        "line_end": line_end,
                        "model_asserted_cwe": "CWE-284",
                        "cwe": "CWE-284",
                        "cve_refs": [],
                        "severity": "high",
                        "confidence": 0.88,
                        "title": "Broad CIDR with ALLOW action",
                        "description": "0.0.0.0/0 combined with allow/permit action.",
                        "evidence": chunk_content[:400],
                        "trace": "scripted: 0.0.0.0/0 allow",
                    }
                )

        if "resource \"aws_security_group_rule\"" in chunk_content and "0.0.0.0/0" in chunk_content:
            findings.append(
                {
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "model_asserted_cwe": "CWE-284",
                    "cwe": "CWE-284",
                    "cve_refs": [],
                    "severity": "high",
                    "confidence": 0.9,
                    "title": "Terraform: security group allows global ingress",
                    "description": "Security group rule exposes 0.0.0.0/0.",
                    "evidence": chunk_content[:400],
                    "trace": "scripted: terraform sg 0.0.0.0/0",
                }
            )

        return findings

    def enrich_finding_prose(self, finding: dict[str, Any]) -> dict[str, Any]:
        """FIXTURE advisory prose for a single finding (scripted engine)."""
        finding_id = str(finding.get("id") or finding.get("finding_id") or "unknown")
        title = finding.get("title") or "Likely issue"
        file_path = finding.get("file_path") or "unknown"
        severity = finding.get("model_asserted_severity") or finding.get("severity") or "medium"
        return {
            "finding_id": finding_id,
            "model_context": (
                "[FIXTURE] Context for human reviewers: "
                f"{title} in `{file_path}` (model severity `{severity}`)."
            ),
            "recommended_actions": [
                "[FIXTURE] Review the changed hunk with your team's security checklist.",
                "[FIXTURE] Confirm whether least-privilege alternatives exist before merge.",
            ],
            "enrichment_source": "scripted-fixture",
            "enrichment_generated_at": _fixture_timestamp(),
        }

    def generate_review_summary(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """FIXTURE advisory review summary (scripted engine)."""
        covered = [str(item.get("id") or "") for item in findings if item.get("id")]
        if not findings:
            return {
                "summary_text": (
                    "[FIXTURE] No likely findings were reported for the changed hunks. "
                    "Advisory fixture prose only."
                ),
                "suggested_course_of_action": (
                    "[FIXTURE] Proceed with your normal human review process for this change."
                ),
                "findings_covered": [],
                "generated_at": _fixture_timestamp(),
                "generator": "scripted-fixture",
                "is_advisory": True,
            }
        titles = ", ".join(str(item.get("title") or "finding") for item in findings[:5])
        return {
            "summary_text": (
                "[FIXTURE] Reviewer summary covering "
                f"{len(findings)} likely finding(s): {titles}. "
                "Advisory fixture prose — not a policy verdict."
            ),
            "suggested_course_of_action": (
                "[FIXTURE] Prioritize remediation discussion for flagged hunks."
            ),
            "findings_covered": covered,
            "generated_at": _fixture_timestamp(),
            "generator": "scripted-fixture",
            "is_advisory": True,
        }


def _fixture_timestamp() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _matches_permissive_firewall(text: str) -> bool:
    patterns = [
        r"any\s+any\s+(allow|permit)",
        r"(allow|permit)\s+\S+\s+any\s+any",
        r"(allow|permit)\s+ip\s+any\s+any",
        r"from\s+any\s+to\s+any\s+(allow|permit)",
        r"source\s*=\s*[\"']?0\.0\.0\.0/0[\"']?",
    ]
    if not any(re.search(p, text) for p in patterns):
        return False
    if "deny" in text and "allow" not in text:
        return False
    if re.search(r"10\.\d+\.\d+\.\d+/|192\.168\.|172\.(1[6-9]|2\d|3[01])\.", text):
        if "0.0.0.0/0" not in text:
            return False
    return "allow" in text or "permit" in text


def _parse_json_findings(
    text: str,
    default_path: str,
    *,
    prepend_array_bracket: bool = False,
) -> list[dict[str, Any]]:
    payload = text or ""
    if prepend_array_bracket:
        stripped = payload.lstrip()
        if stripped and not stripped.startswith("["):
            payload = "[" + payload
    match = re.search(r"\[.*\]", payload, re.DOTALL)
    if not match:
        return []
    try:
        items = json.loads(match.group(0))
    except json.JSONDecodeError:
        return []
    if not isinstance(items, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            item.setdefault("file_path", default_path)
            normalized.append(item)
    return normalized


def build_engine_from_env() -> EvalEngine:
    if os.environ.get("FOUNDATION_SEC_ENGINE", "").lower() == "scripted":
        return ScriptedEvalEngine()

    model_dir, gguf_glob, quant_label, _use_low, manifest_key, model_variant = (
        gguf_settings_from_env()
    )
    default_n_ctx = (
        REASONING_N_CTX_DEFAULT
        if model_variant == MODEL_VARIANT_REASONING
        else int(os.environ.get("FOUNDATION_SEC_N_CTX", "8192"))
    )
    n_ctx = int(os.environ.get("FOUNDATION_SEC_N_CTX", str(default_n_ctx)))
    max_output_tokens = int(
        os.environ.get(
            "FOUNDATION_SEC_MAX_OUTPUT_TOKENS",
            str(
                REASONING_MAX_TOKENS_DEFAULT
                if model_variant == MODEL_VARIANT_REASONING
                else 1024
            ),
        )
    )
    return LlamaCppEvalEngine(
        model_dir,
        gguf_glob=gguf_glob,
        quant_label=quant_label,
        load_strategy=os.environ.get("FOUNDATION_SEC_LOAD_STRATEGY", "on_demand"),
        n_ctx=n_ctx,
        manifest_key=manifest_key,
        model_variant=model_variant,
        max_output_tokens=max_output_tokens,
    )
