"""Tests for instruct chat-template inference helpers."""

from __future__ import annotations

from foundation_sec_server.chat_inference import (
    AUTHORITATIVE_INFERENCE_PATH,
    CHAT_TEMPLATE_FIDELITY_SUMMARY,
    DEFAULT_SYSTEM_PROMPT,
    FOUNDATION_SEC_CHAT_FORMAT,
    FOUNDATION_SEC_CHAT_STOP_TOKENS,
    build_instruct_messages,
    chat_template_fidelity,
    create_chat_completion,
    create_raw_completion,
    run_advisory_completion,
    use_chat_template,
    verify_chat_template_render,
)


class _FakeLlama:
    chat_handler = None
    metadata = {}
    last_prompt: str | None = None
    last_chat_kwargs: dict | None = None

    def __call__(self, prompt: str, **kwargs):
        self.last_prompt = prompt
        self.last_kwargs = kwargs
        return {
            "choices": [{"text": "raw completion reply"}],
            "usage": {"completion_tokens": 3},
        }

    def create_chat_completion(self, **kwargs):
        self.last_chat_kwargs = kwargs
        return {
            "choices": [
                {
                    "message": {
                        "content": "assistant reply",
                    }
                }
            ]
        }


def test_build_instruct_messages_uses_cookbook_default_system_prompt() -> None:
    messages = build_instruct_messages("review this config")
    assert messages == [
        {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
        {"role": "user", "content": "review this config"},
    ]
    assert DEFAULT_SYSTEM_PROMPT == "You are a cybersecurity expert."


def test_create_raw_completion_uses_prompt_string() -> None:
    llm = _FakeLlama()
    text = create_raw_completion(llm, "eval prompt", stop=["```"])
    assert text == "raw completion reply"
    assert llm.last_prompt == "eval prompt"
    assert llm.last_kwargs is not None
    assert llm.last_kwargs["stop"] == ["```"]


def test_run_advisory_completion_defaults_to_raw(monkeypatch) -> None:
    monkeypatch.delenv("FOUNDATION_SEC_USE_CHAT_TEMPLATE", raising=False)
    llm = _FakeLlama()
    text = run_advisory_completion(llm, "eval prompt", stop=["```"])
    assert text == "raw completion reply"
    assert llm.last_chat_kwargs is None


def test_run_advisory_completion_uses_chat_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("FOUNDATION_SEC_USE_CHAT_TEMPLATE", "true")
    llm = _FakeLlama()
    text = run_advisory_completion(llm, "eval prompt", stop=["```"])
    assert text == "assistant reply"
    assert llm.last_chat_kwargs is not None
    assert llm.last_chat_kwargs["stop"]


def test_create_chat_completion_uses_chat_api_with_role_marker_stops() -> None:
    llm = _FakeLlama()
    text = create_chat_completion(
        llm,
        "user task",
        max_tokens=128,
        temperature=0.0,
        stop=["```"],
    )
    assert text == "assistant reply"
    assert llm.last_chat_kwargs is not None
    assert llm.last_chat_kwargs["messages"][0]["role"] == "system"
    assert llm.last_chat_kwargs["messages"][1]["content"] == "user task"
    assert "<|system|>" in llm.last_chat_kwargs["stop"]
    assert "```" in llm.last_chat_kwargs["stop"]


def test_chat_template_fidelity_reports_raw_completion_by_default(monkeypatch) -> None:
    monkeypatch.delenv("FOUNDATION_SEC_USE_CHAT_TEMPLATE", raising=False)
    fidelity = chat_template_fidelity(_FakeLlama())
    assert fidelity["fidelity_summary"] == CHAT_TEMPLATE_FIDELITY_SUMMARY
    assert fidelity["inference_path"] == AUTHORITATIVE_INFERENCE_PATH
    assert fidelity["llama_cpp_chat_format"] == "raw_completion"
    assert fidelity["uses_model_specific_jinja_template"] is False
    assert "raw completion" in fidelity["fidelity_note"]


def test_chat_template_fidelity_reports_chat_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("FOUNDATION_SEC_USE_CHAT_TEMPLATE", "true")
    llm = _FakeLlama()
    llm.chat_handler = object()
    fidelity = chat_template_fidelity(llm)
    assert fidelity["inference_path"] == "chat_template"
    assert fidelity["llama_cpp_chat_format"] == FOUNDATION_SEC_CHAT_FORMAT
    assert fidelity["uses_model_specific_jinja_template"] is True


def test_verify_chat_template_render_matches_repo_template() -> None:
    result = verify_chat_template_render(
        "You are a security auditor reviewing a configuration file. "
        "List one misconfiguration, severity, and recommended fix."
    )
    assert result["identical"] is True
    assert "<|system|>" in result["handler_render"]
    assert result["handler_render"].endswith("<|assistant|>\n")


def test_role_marker_stop_tokens_exclude_llama3_eot() -> None:
    assert "<|eot_id|>" not in FOUNDATION_SEC_CHAT_STOP_TOKENS


def test_use_chat_template_false_by_default(monkeypatch) -> None:
    monkeypatch.delenv("FOUNDATION_SEC_USE_CHAT_TEMPLATE", raising=False)
    assert use_chat_template() is False
