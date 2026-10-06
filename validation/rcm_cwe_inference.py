"""Local llama.cpp completion for validation harnesses (shared advisory chat path)."""

from __future__ import annotations

import gc
import os
import platform
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_FSEC = _ROOT / "services" / "foundation-sec-server"
if str(_FSEC) not in sys.path:
    sys.path.insert(0, str(_FSEC))

from foundation_sec_server.chat_inference import (  # noqa: E402
    build_foundation_sec_chat_handler,
    chat_template_fidelity,
    run_advisory_completion,
    use_chat_template,
)


class LlamaCompleteEngine:
    """Minimal GGUF completion wrapper for RCM prompts (no detection path)."""

    def __init__(
        self,
        model_dir: Path,
        *,
        gguf_glob: str = "*.gguf",
        quant_label: str,
        n_ctx: int = 4096,
    ) -> None:
        self._model_dir = model_dir
        self._gguf_glob = gguf_glob
        self._quant_label = quant_label
        self._n_ctx = n_ctx
        self._gguf_path = self._resolve_gguf()
        self._llm: Any | None = None

    @property
    def gguf_file(self) -> str:
        return self._gguf_path.name

    @property
    def model_dir(self) -> str:
        return str(self._model_dir)

    def _resolve_gguf(self) -> Path:
        if not self._model_dir.is_dir():
            raise FileNotFoundError(f"Model directory not found: {self._model_dir}")
        matches = sorted(
            path
            for path in self._model_dir.iterdir()
            if path.is_file() and fnmatch(path.name, self._gguf_glob)
        )
        if not matches:
            raise FileNotFoundError(
                f"No GGUF matching {self._gguf_glob!r} under {self._model_dir}"
            )
        if len(matches) > 1:
            raise FileNotFoundError(
                f"Multiple GGUF files under {self._model_dir}: "
                f"{', '.join(item.name for item in matches)}"
            )
        return matches[0]

    def load(self) -> None:
        if self._llm is not None:
            return
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        from llama_cpp import Llama

        n_gpu_layers = -1 if platform.system() == "Darwin" else 0
        llama_kwargs: dict[str, Any] = {
            "model_path": str(self._gguf_path),
            "n_ctx": self._n_ctx,
            "n_gpu_layers": n_gpu_layers,
            "verbose": False,
        }
        if use_chat_template():
            llama_kwargs["chat_handler"] = build_foundation_sec_chat_handler()
        self._llm = Llama(**llama_kwargs)

    def unload(self) -> None:
        if self._llm is None:
            return
        del self._llm
        self._llm = None
        gc.collect()

    def complete(
        self,
        prompt: str,
        *,
        max_tokens: int = 128,
        temperature: float = 0.1,
        repeat_penalty: float = 1.2,
        stop: list[str] | None = None,
    ) -> str:
        text, _ = self.complete_with_usage(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            repeat_penalty=repeat_penalty,
            stop=stop,
        )
        return text

    def complete_with_usage(
        self,
        prompt: str,
        *,
        max_tokens: int = 128,
        temperature: float = 0.1,
        repeat_penalty: float = 1.2,
        stop: list[str] | None = None,
    ) -> tuple[str, dict[str, int | bool]]:
        self.load()
        assert self._llm is not None
        output = self._llm(
            prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            repeat_penalty=repeat_penalty,
            stop=stop or ["\n\n\n"],
        )
        choice = output["choices"][0]
        usage = output.get("usage") or {}
        completion_tokens = int(usage.get("completion_tokens") or 0)
        finish_reason = str(choice.get("finish_reason") or "")
        hit_max_tokens = completion_tokens >= max_tokens or finish_reason == "length"
        return str(choice.get("text") or ""), {
            "completion_tokens": completion_tokens,
            "hit_max_tokens": hit_max_tokens,
            "finish_reason": finish_reason,
        }

    def chat_template_fidelity(self) -> dict[str, Any]:
        self.load()
        assert self._llm is not None
        return chat_template_fidelity(self._llm)


def resolve_staged_model_dir(candidates: list[Path]) -> Path | None:
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        try:
            LlamaCompleteEngine(candidate, quant_label=candidate.name)
        except FileNotFoundError:
            continue
        return candidate
    return None
