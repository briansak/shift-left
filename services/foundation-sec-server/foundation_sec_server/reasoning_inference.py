"""Foundation-Sec-8B-Reasoning inference — cookbook ReasoningModelClient parity."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from foundation_sec_server.model_profiles import (
    REASONING_MAX_TOKENS_DEFAULT,
    REASONING_SPLIT_END,
    REASONING_SPLIT_START,
    MODEL_VARIANT_REASONING,
)

# Cookbook ReasoningModelClient defaults (config-assessment / prose evals).
REASONING_TEMPERATURE = 0.3
REASONING_DO_SAMPLE = True
REASONING_CHAT_TEMPLATE_FILENAME = "chat_template.jinja"
REASONING_HF_TEMPLATE_URL = (
    "https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF/"
    "raw/main/tokenizer_config.json"
)

# Observed when the model continues after template-injected <think> without closing.
FALLBACK_MARKER_H3 = "\n\n### "
FALLBACK_MARKER_BASED_ON = "\n\nBased on the provided"
FALLBACK_MARKER_H2 = "\n\n## "

SPLIT_METHOD_CLOSED_TAG = "closed_tag"
SPLIT_METHOD_FALLBACK_H3 = "fallback_triple_hash"
SPLIT_METHOD_FALLBACK_BASED_ON = "fallback_based_on_provided"
SPLIT_METHOD_FALLBACK_H2 = "fallback_double_hash"
SPLIT_METHOD_WHOLE_COMPLETION = "whole_completion_as_answer"
SPLIT_METHOD_SPLIT_FAILURE = "split_failure"


@dataclass(frozen=True)
class ReasoningCompletion:
    raw_text: str
    reasoning: str
    answer: str
    delimiter_start: str
    delimiter_end: str
    delimiter_observed: str
    split_method: str
    split_failure: bool
    emitted_close_tag: bool
    emitted_open_tag: bool
    reasoning_token_count: int | None
    answer_token_count: int | None
    completion_token_count: int | None


class ReasoningModelClient:
    """Cookbook-aligned client for Foundation-Sec-8B-Reasoning (Q4_K_M)."""

    def __init__(
        self,
        llm: Any,
        *,
        model_dir: Path | None = None,
        temperature: float = REASONING_TEMPERATURE,
        max_tokens: int = REASONING_MAX_TOKENS_DEFAULT,
        do_sample: bool = REASONING_DO_SAMPLE,
    ) -> None:
        self._llm = llm
        self._model_dir = model_dir
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._do_sample = do_sample

    @property
    def model_variant(self) -> str:
        return MODEL_VARIANT_REASONING

    def complete(self, user_content: str, *, system_prompt: str | None = None) -> ReasoningCompletion:
        prompt = render_reasoning_prompt(user_content, system_prompt=system_prompt)
        return self.complete_prompt(prompt)

    def complete_raw(self, user_content: str) -> ReasoningCompletion:
        """Raw completion — no chat template, no injected thinking prefix."""
        raw = self._generate(user_content)
        return split_reasoning_answer(
            raw,
            token_counter=self._llm,
            prompt_for_token_count=user_content,
        )

    def complete_prompt(self, prompt: str) -> ReasoningCompletion:
        """Run completion on a fully rendered prompt (eval harness / JSON variants)."""
        raw = self._generate(prompt)
        return split_reasoning_answer(
            raw,
            token_counter=self._llm,
            prompt_for_token_count=prompt,
        )

    def _generate(self, prompt: str) -> str:
        kwargs: dict[str, Any] = {
            "max_tokens": self._max_tokens,
            "temperature": self._temperature,
            "stop": ["<|end_of_text|>", "<|system|>", "<|user|>"],
        }
        if self._do_sample:
            kwargs.setdefault("top_p", 0.95)
        output = self._llm(prompt, **kwargs)
        choice = output["choices"][0]
        return str(choice.get("text") or "")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def reasoning_model_dir() -> Path:
    override = os.environ.get("FOUNDATION_SEC_MODEL_PATH", "").strip()
    if override:
        return Path(override)
    return _repo_root() / "models" / "foundation-sec-reasoning-q4_k_m"


def reasoning_chat_template_path(model_dir: Path | None = None) -> Path:
    base = model_dir or reasoning_model_dir()
    return base / REASONING_CHAT_TEMPLATE_FILENAME


def fetch_reasoning_chat_template_source() -> str:
    import json
    import urllib.request

    with urllib.request.urlopen(REASONING_HF_TEMPLATE_URL, timeout=60) as response:
        payload = json.loads(response.read())
    template = payload.get("chat_template")
    if not template:
        raise FileNotFoundError(
            "tokenizer_config.json on HF has no chat_template for Foundation-Sec-8B-Reasoning."
        )
    return str(template)


def load_reasoning_chat_template_source(model_dir: Path | None = None) -> str:
    path = reasoning_chat_template_path(model_dir)
    if path.is_file():
        return path.read_text(encoding="utf-8")
    return fetch_reasoning_chat_template_source()


def materialize_reasoning_chat_template(model_dir: Path | None = None) -> Path:
    """Persist HF chat_template.jinja under the reasoning weights directory."""
    base = model_dir or reasoning_model_dir()
    base.mkdir(parents=True, exist_ok=True)
    path = reasoning_chat_template_path(base)
    if not path.is_file():
        path.write_text(fetch_reasoning_chat_template_source(), encoding="utf-8")
    return path


@lru_cache(maxsize=1)
def _reasoning_formatter_source(model_dir: str) -> str:
    return load_reasoning_chat_template_source(Path(model_dir))


def render_reasoning_prompt(
    user_content: str,
    *,
    system_prompt: str | None = None,
    model_dir: Path | None = None,
    force_thinking_prefix: bool = True,
) -> str:
    """Render the chat prompt; optionally mirror cookbook manual thinking prefix."""
    from jinja2 import Environment

    base = model_dir or reasoning_model_dir()
    template_source = _reasoning_formatter_source(str(base.resolve()))
    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_content})
    rendered = (
        Environment(autoescape=False)
        .from_string(template_source)
        .render(
            messages=messages,
            add_generation_prompt=True,
            eos_token="<|end_of_text|>",
            bos_token="",
        )
    )
    if not rendered.startswith("<|begin_of_text|>"):
        rendered = "<|begin_of_text|>" + rendered
    if force_thinking_prefix and REASONING_SPLIT_START not in rendered:
        # Cookbook may force the prefix when not using the HF template path.
        rendered = f"{rendered.rstrip()}{REASONING_SPLIT_START}\n"
    return rendered


def classify_reasoning_split(raw_text: str) -> tuple[str, str, str, str, bool, bool, bool]:
    """Return reasoning, answer, split_method, delimiter_observed, split_failure, open_tag, close_tag."""
    text = raw_text or ""
    emitted_open = REASONING_SPLIT_START in text
    emitted_close = REASONING_SPLIT_END in text

    if emitted_close:
        before, answer = text.split(REASONING_SPLIT_END, 1)
        if REASONING_SPLIT_START in before:
            reasoning = before.split(REASONING_SPLIT_START, 1)[-1].strip()
        else:
            reasoning = before.strip()
        answer = answer.strip()
        method = SPLIT_METHOD_CLOSED_TAG
        observed = f"{REASONING_SPLIT_START}...{REASONING_SPLIT_END}"
    elif emitted_open:
        reasoning = text.split(REASONING_SPLIT_START, 1)[-1].strip()
        answer = ""
        method = SPLIT_METHOD_SPLIT_FAILURE
        observed = f"{REASONING_SPLIT_START} without {REASONING_SPLIT_END}"
    elif (idx := text.find(FALLBACK_MARKER_H3)) != -1:
        reasoning = text[:idx].strip()
        answer = text[idx:].lstrip("\n").strip()
        method = SPLIT_METHOD_FALLBACK_H3
        observed = f"fallback before {FALLBACK_MARKER_H3!r}"
    elif (idx := text.find(FALLBACK_MARKER_BASED_ON)) != -1:
        reasoning = text[:idx].strip()
        answer = text[idx:].lstrip("\n").strip()
        method = SPLIT_METHOD_FALLBACK_BASED_ON
        observed = f"fallback before {FALLBACK_MARKER_BASED_ON!r}"
    elif (idx := text.find(FALLBACK_MARKER_H2)) != -1:
        reasoning = text[:idx].strip()
        answer = text[idx:].lstrip("\n").strip()
        method = SPLIT_METHOD_FALLBACK_H2
        observed = f"fallback before {FALLBACK_MARKER_H2!r}"
    else:
        reasoning = ""
        answer = text.strip()
        method = SPLIT_METHOD_WHOLE_COMPLETION
        observed = "no delimiter or fallback marker; entire completion is answer"

    split_failure = not (answer or "").strip()
    if split_failure:
        method = SPLIT_METHOD_SPLIT_FAILURE
    return reasoning, answer, method, observed, split_failure, emitted_open, emitted_close


def diagnostic_prose_answer_split(raw_text: str) -> tuple[str, str, str]:
    """Diagnostics only — separate reasoning prose from JSON/scored tail.

    Used when :func:`classify_reasoning_split` yields ``whole_completion_as_answer``
    (no ``</think>`` or fallback markers). Does not affect scoring.
    """
    text = raw_text or ""
    for marker in ("```json", "\n\n[", "\n["):
        idx = text.find(marker)
        if idx != -1:
            return text[:idx].strip(), text[idx:].strip(), f"prose_before_{marker!r}"
    return "", text.strip(), "whole_completion_no_json_marker"


def diagnostic_token_split(
    raw_text: str,
    *,
    token_counter: Any | None = None,
) -> dict[str, Any]:
    """Return diagnostic reasoning/answer token counts for reporting."""
    reasoning, answer, split_method, *_rest = classify_reasoning_split(raw_text)
    method = split_method
    if split_method == SPLIT_METHOD_WHOLE_COMPLETION and not reasoning.strip():
        reasoning, answer, method = diagnostic_prose_answer_split(raw_text)

    r_tok, a_tok, c_tok = _token_counts(
        token_counter,
        prompt=None,
        reasoning=reasoning,
        answer=answer,
        raw=raw_text or "",
    )
    return {
        "diagnostic_split_method": method,
        "reasoning_token_count": r_tok,
        "answer_token_count": a_tok,
        "completion_token_count": c_tok,
        "reasoning_char_count": len(reasoning),
        "answer_char_count": len(answer),
    }


def scoring_surface(completion: ReasoningCompletion) -> str:
    """Text used for semantic-fit / detection scoring (whole model completion).

    Heuristic ``answer`` splits from :func:`classify_reasoning_split` are retained
    on :class:`ReasoningCompletion` for diagnostics only — never use them as the
    scored surface when ``split_failure`` is false but the split is non-canonical.
    """
    return completion.raw_text or ""


def split_reasoning_answer(
    raw_text: str,
    *,
    token_counter: Any | None = None,
    prompt_for_token_count: str | None = None,
) -> ReasoningCompletion:
    """Split model output into reasoning trace and scored answer.

    When ``split_failure`` is true the answer is empty — eval harnesses must record
    ``split_failure`` and never treat the file as zero findings.
    """
    reasoning, answer, method, observed, split_failure, emitted_open, emitted_close = (
        classify_reasoning_split(raw_text)
    )
    text = raw_text or ""

    reasoning_tokens, answer_tokens, completion_tokens = _token_counts(
        token_counter,
        prompt=prompt_for_token_count,
        reasoning=reasoning,
        answer=answer,
        raw=text,
    )
    return ReasoningCompletion(
        raw_text=text,
        reasoning=reasoning,
        answer=answer,
        delimiter_start=REASONING_SPLIT_START,
        delimiter_end=REASONING_SPLIT_END,
        delimiter_observed=observed,
        split_method=method,
        split_failure=split_failure,
        emitted_open_tag=emitted_open,
        emitted_close_tag=emitted_close,
        reasoning_token_count=reasoning_tokens,
        answer_token_count=answer_tokens,
        completion_token_count=completion_tokens,
    )


def answer_is_parseable(answer: str, *, mode: str = "prose") -> tuple[bool, str]:
    """Lightweight parseability gate for Phase 1 smoke tests."""
    stripped = (answer or "").strip()
    if not stripped:
        return False, "empty answer after reasoning split"
    if mode == "prose":
        if len(stripped) < 20:
            return False, "answer shorter than 20 characters"
        if stripped in {"]", "}", "://"}:
            return False, f"degenerate answer literal: {stripped!r}"
        if re.fullmatch(r"[\]:/]+", stripped):
            return False, "degenerate punctuation-only answer"
        return True, "prose answer present"
    return True, "ok"


def _token_counts(
    token_counter: Any | None,
    *,
    prompt: str | None,
    reasoning: str,
    answer: str,
    raw: str,
) -> tuple[int | None, int | None, int | None]:
    if token_counter is None:
        return None, None, None
    tokenize = getattr(token_counter, "tokenize", None)
    if not callable(tokenize):
        return None, None, None
    try:
        reasoning_tokens = len(tokenize(reasoning.encode("utf-8"))) if reasoning else 0
        answer_tokens = len(tokenize(answer.encode("utf-8"))) if answer else 0
        completion_tokens = len(tokenize(raw.encode("utf-8"))) if raw else 0
        return reasoning_tokens, answer_tokens, completion_tokens
    except Exception:  # noqa: BLE001
        return None, None, None
