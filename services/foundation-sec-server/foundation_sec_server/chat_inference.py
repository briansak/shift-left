"""Foundation-Sec inference helpers — raw completion (default) and optional chat template."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_SYSTEM_PROMPT = "You are a cybersecurity expert."

# Authoritative production path for structured JSON evals (see chat-template-finding.md).
AUTHORITATIVE_INFERENCE_PATH = "raw_completion"
CHAT_TEMPLATE_FIDELITY_SUMMARY = (
    "raw completion (authoritative); model's own chat_template.jinja available but "
    "produces empty findings on 77/87 files - see chat-truncation-diagnostic.json"
)

FOUNDATION_SEC_EOS_TOKEN = "<|end_of_text|>"
FOUNDATION_SEC_BOS_TOKEN = "<|begin_of_text|>"
FOUNDATION_SEC_CHAT_TEMPLATE_FILENAME = "foundation-sec-chat-template.jinja"
FOUNDATION_SEC_CHAT_FORMAT = "foundation-sec-jinja"

FOUNDATION_SEC_ROLE_MARKERS = ("<|system|>", "<|user|>", "<|assistant|>")
FOUNDATION_SEC_CHAT_STOP_TOKENS = [
    *FOUNDATION_SEC_ROLE_MARKERS,
    FOUNDATION_SEC_EOS_TOKEN,
]

def use_chat_template() -> bool:
    return os.environ.get("FOUNDATION_SEC_USE_CHAT_TEMPLATE", "").lower() in {
        "1",
        "true",
        "yes",
    }


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def chat_template_path() -> Path:
    return _repo_root() / "models" / FOUNDATION_SEC_CHAT_TEMPLATE_FILENAME


def load_chat_template_source() -> str:
    path = chat_template_path()
    if not path.is_file():
        raise FileNotFoundError(
            f"Foundation-Sec chat template missing: {path}. "
            "Bundle models/foundation-sec-chat-template.jinja for offline inference."
        )
    return path.read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def build_foundation_sec_chat_formatter() -> Any:
    from llama_cpp.llama_chat_format import Jinja2ChatFormatter

    return Jinja2ChatFormatter(
        load_chat_template_source(),
        eos_token=FOUNDATION_SEC_EOS_TOKEN,
        bos_token=FOUNDATION_SEC_BOS_TOKEN,
        add_generation_prompt=True,
    )


def build_foundation_sec_chat_handler() -> Any:
    return build_foundation_sec_chat_formatter().to_chat_handler()


def build_instruct_messages(
    user_content: str,
    *,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
    ]


def render_chat_prompt(
    user_content: str,
    *,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> str:
    formatter = build_foundation_sec_chat_formatter()
    response = formatter(
        messages=build_instruct_messages(user_content, system_prompt=system_prompt),
    )
    return str(response.prompt)


def verify_chat_template_render(
    user_content: str,
    *,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> dict[str, Any]:
    """Render via Jinja2ChatFormatter and confirm byte-identical to template file render."""
    from jinja2 import Environment

    template_source = load_chat_template_source()
    messages = build_instruct_messages(user_content, system_prompt=system_prompt)
    manual = (
        Environment(autoescape=False)
        .from_string(template_source)
        .render(
            messages=messages,
            add_generation_prompt=True,
            eos_token=FOUNDATION_SEC_EOS_TOKEN,
        )
    )
    via_handler = render_chat_prompt(user_content, system_prompt=system_prompt)
    return {
        "identical": manual == via_handler,
        "manual_render": manual,
        "handler_render": via_handler,
        "template_path": str(chat_template_path()),
    }


def chat_template_fidelity(llm: Any | None = None) -> dict[str, Any]:
    """Report inference-path fidelity for server health and eval artifact stamping."""
    metadata = getattr(llm, "metadata", None) or {} if llm is not None else {}
    embedded = metadata.get("tokenizer.chat_template")
    chat_enabled = use_chat_template()
    chat_handler = getattr(llm, "chat_handler", None) if llm is not None else None
    return {
        "fidelity_summary": CHAT_TEMPLATE_FIDELITY_SUMMARY,
        "inference_path": AUTHORITATIVE_INFERENCE_PATH if not chat_enabled else "chat_template",
        "chat_template_enabled": chat_enabled,
        "llama_cpp_chat_format": FOUNDATION_SEC_CHAT_FORMAT if chat_enabled else "raw_completion",
        "gguf_embedded_chat_template": bool(embedded),
        "uses_model_specific_jinja_template": chat_enabled,
        "chat_template_path": str(chat_template_path()),
        "chat_template_available_offline": chat_template_path().is_file(),
        "role_markers": list(FOUNDATION_SEC_ROLE_MARKERS),
        "eos_token": FOUNDATION_SEC_EOS_TOKEN,
        "uses_custom_chat_handler": chat_handler is not None and chat_enabled,
        "fidelity_note": (
            "Production uses llama.cpp raw completion on the eval prompt string. "
            "Set FOUNDATION_SEC_USE_CHAT_TEMPLATE=true to opt into repo-bundled "
            "chat_template.jinja (evaluated and rejected for structured JSON)."
            if not chat_enabled
            else (
                "Opt-in chat_template.jinja via Jinja2ChatFormatter "
                "(<|system|>/<|user|>/<|assistant|>)."
            )
        ),
    }


def _completion_tokens(output: dict[str, Any]) -> int:
    usage = output.get("usage") or {}
    try:
        return int(usage.get("completion_tokens") or 0)
    except (TypeError, ValueError):
        return 0


def create_raw_completion_with_usage(
    llm: Any,
    prompt: str,
    *,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    stop: list[str] | None = None,
) -> tuple[str, int]:
    output = llm(
        prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        stop=stop or ["```"],
    )
    choice = output["choices"][0]
    return str(choice.get("text") or ""), _completion_tokens(output)


def create_raw_completion(
    llm: Any,
    prompt: str,
    *,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    stop: list[str] | None = None,
) -> str:
    text, _tokens = create_raw_completion_with_usage(
        llm,
        prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        stop=stop,
    )
    return text


def run_advisory_completion_with_usage(
    llm: Any,
    prompt: str,
    *,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    stop: list[str] | None = None,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> tuple[str, int]:
    """Dispatch to raw completion (default) or chat template when explicitly enabled."""
    caller_stop = stop or ["```"]
    if use_chat_template():
        return create_chat_completion_with_usage(
            llm,
            prompt,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            stop=caller_stop,
        )
    return create_raw_completion_with_usage(
        llm,
        prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        stop=caller_stop,
    )


def run_advisory_completion(
    llm: Any,
    prompt: str,
    *,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    stop: list[str] | None = None,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> str:
    """Dispatch to raw completion (default) or chat template when explicitly enabled."""
    text, _tokens = run_advisory_completion_with_usage(
        llm,
        prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        stop=stop,
        system_prompt=system_prompt,
    )
    return text


def _merge_stop_tokens(stop: list[str] | None) -> list[str]:
    merged = list(FOUNDATION_SEC_CHAT_STOP_TOKENS)
    for token in stop or []:
        if token not in merged:
            merged.append(token)
    return merged


def create_chat_completion_with_usage(
    llm: Any,
    user_content: str,
    *,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    repeat_penalty: float = 1.2,
    stop: list[str] | None = None,
) -> tuple[str, int]:
    messages = build_instruct_messages(user_content, system_prompt=system_prompt)
    output = llm.create_chat_completion(
        messages=messages,
        max_tokens=max_tokens,
        temperature=temperature,
        repeat_penalty=repeat_penalty,
        stop=_merge_stop_tokens(stop),
    )
    choice = output["choices"][0]
    message = choice.get("message") or {}
    return str(message.get("content") or ""), _completion_tokens(output)


def create_chat_completion(
    llm: Any,
    user_content: str,
    *,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    max_tokens: int = 1024,
    temperature: float = 0.1,
    repeat_penalty: float = 1.2,
    stop: list[str] | None = None,
) -> str:
    text, _tokens = create_chat_completion_with_usage(
        llm,
        user_content,
        system_prompt=system_prompt,
        max_tokens=max_tokens,
        temperature=temperature,
        repeat_penalty=repeat_penalty,
        stop=stop,
    )
    return text
