"""Platform-aware model backend selection and on-demand loading."""

from __future__ import annotations

import logging
import os
import platform
import threading
import time
from pathlib import Path
from typing import Any

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from antares_server.contract import parse_and_validate_findings
from shift_left_shared.weights import load_prewarm_manifest, verify_antares_weights

logger = logging.getLogger(__name__)

OUTCOME_COMPLETED_NO_FINDINGS = "completed_no_findings"
OUTCOME_COMPLETED_WITH_FINDINGS = "completed_with_findings"
OUTCOME_FAILED = "failed"

DEFAULT_AGENT_MAX_NEW_TOKENS = 2048


def agent_max_new_tokens() -> int:
    """Max tokens per agent-loop generation (output budget, not context window)."""
    raw = os.environ.get("ANTARES_AGENT_MAX_NEW_TOKENS", str(DEFAULT_AGENT_MAX_NEW_TOKENS))
    try:
        value = int(raw)
    except ValueError:
        value = DEFAULT_AGENT_MAX_NEW_TOKENS
    return max(256, value)

_ANALYSIS_PROMPT = """You are Antares, a security model that localizes likely vulnerabilities in code changes.
Analyze the diff hunk below and respond with ONLY a JSON array (no markdown fences).
Each object must include:
  file_path, line_start, line_end, cwe, severity (info|low|medium|high|critical),
  confidence (0.0-1.0), title, description, evidence, trace

If no likely issue is present, return [].

File: {file_path}
Lines: {line_start}-{line_end}
```diff
{content}
```
JSON array:"""


class AntaresEngine:
    def __init__(
        self,
        model_path: str,
        *,
        backend: str = "auto",
        load_strategy: str = "on_demand",
    ) -> None:
        self._model_path = Path(model_path)
        self._backend = backend
        self._load_strategy = load_strategy
        self._device = self._resolve_device(backend)
        self._tokenizer: Any | None = None
        self._model: Any | None = None
        self._lock = threading.Lock()
        self._run_count = 0
        self._recycle_after_runs = int(os.environ.get("ANTARES_RECYCLE_AFTER_RUNS", "10"))

    @staticmethod
    def _resolve_device(backend: str) -> str:
        if backend != "auto":
            return backend
        if torch.backends.mps.is_available():
            return "mps"
        if torch.cuda.is_available():
            return "cuda"
        return "cpu"

    @staticmethod
    def _resolve_dtype(device: str) -> torch.dtype:
        """Match staged weights (config.json uses bfloat16). Avoid float16 on MPS — NaN logits."""
        if device == "cpu":
            return torch.float32
        if device == "mps":
            return torch.bfloat16
        if device == "cuda":
            return torch.float16
        return torch.float32

    def assert_model_present(self) -> None:
        if not self._model_path.exists():
            raise FileNotFoundError(
                f"Antares weights not found at {self._model_path}. "
                "Pre-stage local weights before starting (hf download — operator egress only)."
            )
        if not (self._model_path / "config.json").exists():
            raise FileNotFoundError(
                f"Invalid model directory {self._model_path}: missing config.json."
            )
        repo_root = self._model_path.parent.parent
        manifest = load_prewarm_manifest(repo_root)
        try:
            verify_antares_weights(self._model_path, manifest)
        except Exception as exc:
            raise FileNotFoundError(str(exc)) from exc

    def assert_local_weights_only(self) -> None:
        """Fail closed if remote weight download would be attempted."""
        import os

        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
        if os.environ.get("HF_HUB_DISABLE_IMPLICIT_TOKEN", "").lower() not in {"1", "true"}:
            os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")

    def load(self) -> None:
        with self._lock:
            if self._model is not None:
                return
            self.assert_model_present()
            self.assert_local_weights_only()
            logger.info(
                "Loading Antares from %s on device=%s",
                self._model_path,
                self._device,
            )
            # GraniteMoeHybrid architecture — local snapshot only.
            self._tokenizer = AutoTokenizer.from_pretrained(
                str(self._model_path),
                local_files_only=True,
            )
            dtype = self._resolve_dtype(self._device)
            self._model = AutoModelForCausalLM.from_pretrained(
                str(self._model_path),
                local_files_only=True,
                torch_dtype=dtype,
            )
            self._model.to(self._device)
            self._model.eval()

    def unload(self) -> None:
        with self._lock:
            if self._model is None:
                return
            del self._model
            del self._tokenizer
            self._model = None
            self._tokenizer = None
            if self._device == "cuda":
                torch.cuda.empty_cache()
            elif self._device == "mps":
                torch.mps.empty_cache()
            import gc

            gc.collect()
            logger.info("Antares model unloaded")

    def unload_after_run(self) -> dict[str, Any]:
        """Unload model at triage run completion; recycle after configured run count."""
        self.unload()
        self._run_count += 1
        recycled = False
        if self._run_count >= self._recycle_after_runs:
            import gc

            gc.collect()
            self._run_count = 0
            recycled = True
            logger.warning(
                "Antares recycle threshold reached (%s runs) — process restart recommended",
                self._recycle_after_runs,
            )
        return {"runs_since_recycle": self._run_count, "recycled": recycled}

    def analyze_files(self, files: list[dict[str, Any]]) -> dict[str, Any]:
        started = time.monotonic()
        timings: dict[str, int] = {}
        try:
            if self._load_strategy == "on_demand":
                self.load()
            elif self._model is None:
                self.load()

            assert self._model is not None and self._tokenizer is not None
            findings: list[dict[str, Any]] = []

            for file_entry in files:
                path = file_entry["path"]
                for hunk in file_entry.get("hunks", []):
                    try:
                        prompt = _ANALYSIS_PROMPT.format(
                            file_path=path,
                            line_start=hunk.get("new_start", 1),
                            line_end=hunk.get("new_end", hunk.get("new_start", 1)),
                            content=hunk.get("content", "")[:4000],
                        )
                        raw = self._generate(prompt)
                        parsed = self._parse_findings(raw, path)
                        if not parsed.ok:
                            timings["total"] = int((time.monotonic() - started) * 1000)
                            return {
                                "outcome": OUTCOME_FAILED,
                                "findings": [],
                                "failure_class": "parse_error",
                                "failure_stage": "generation",
                                "failure_message": parsed.failure_message,
                                "timings_ms": timings,
                            }
                        findings.extend(parsed.findings)
                    except Exception as exc:  # noqa: BLE001
                        timings["total"] = int((time.monotonic() - started) * 1000)
                        return {
                            "outcome": OUTCOME_FAILED,
                            "findings": [],
                            "failure_class": "chunk_error",
                            "failure_stage": "chunk",
                            "failure_message": str(exc),
                            "timings_ms": timings,
                        }
        except Exception as exc:  # noqa: BLE001
            timings["total"] = int((time.monotonic() - started) * 1000)
            return {
                "outcome": OUTCOME_FAILED,
                "findings": [],
                "failure_class": "inference_error",
                "failure_stage": "generation",
                "failure_message": str(exc),
                "timings_ms": timings,
            }
        finally:
            if self._load_strategy == "on_demand":
                self.unload()

        timings["total"] = int((time.monotonic() - started) * 1000)
        outcome = (
            OUTCOME_COMPLETED_WITH_FINDINGS if findings else OUTCOME_COMPLETED_NO_FINDINGS
        )
        return {
            "outcome": outcome,
            "findings": findings,
            "failure_class": None,
            "failure_stage": None,
            "failure_message": None,
            "timings_ms": timings,
        }

    def _generate(self, prompt: str) -> str:
        return self.generate_agent(prompt, temperature=0.0, top_p=1.0, do_sample=False)

    def generate_agent(
        self,
        prompt: str,
        *,
        temperature: float = 0.3,
        top_p: float = 1.0,
        do_sample: bool | None = None,
        max_new_tokens: int | None = None,
    ) -> str:
        assert self._model is not None and self._tokenizer is not None
        if max_new_tokens is None:
            max_new_tokens = agent_max_new_tokens()
        sample = do_sample if do_sample is not None else temperature > 0.0
        inputs = self._tokenizer(prompt, return_tensors="pt").to(self._device)
        with torch.no_grad():
            output = self._model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=sample,
                temperature=temperature if sample else None,
                top_p=top_p if sample else None,
                pad_token_id=self._tokenizer.pad_token_id or self._tokenizer.eos_token_id,
            )
        generated = output[0][inputs["input_ids"].shape[-1] :]
        return self._tokenizer.decode(generated, skip_special_tokens=True)

    @staticmethod
    def _parse_findings(text: str, default_path: str) -> Any:
        from antares_server.contract import ContractParseResult

        result = parse_and_validate_findings(text, default_path=default_path)
        if not result.ok:
            logger.warning(
                "Antares contract validation failed for %s: %s",
                default_path,
                result.failure_message,
            )
            return ContractParseResult(
                ok=False,
                failure_message=result.failure_message or "contract validation failed",
                violations=result.violations,
                had_markdown_fence=result.had_markdown_fence,
            )
        return ContractParseResult(ok=True, findings=result.findings)

    def status(self) -> dict[str, Any]:
        return {
            "model_path": str(self._model_path),
            "backend": self._backend,
            "device": self._device,
            "platform": platform.platform(),
            "loaded": self._model is not None,
            "load_strategy": self._load_strategy,
        }


def build_engine_from_env() -> AntaresEngine:
    model_path = os.environ.get("ANTARES_MODEL_PATH", "/models/antares")
    backend = os.environ.get("ANTARES_BACKEND", "auto")
    load_strategy = os.environ.get("ANTARES_LOAD_STRATEGY", "on_demand")
    engine = AntaresEngine(model_path, backend=backend, load_strategy=load_strategy)
    engine.assert_model_present()
    return engine
