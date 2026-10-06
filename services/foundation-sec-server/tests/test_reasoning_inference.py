"""Tests for Foundation-Sec-8B-Reasoning inference helpers."""

from __future__ import annotations

from foundation_sec_server.model_profiles import (
    MODEL_VARIANT_REASONING,
    assert_gguf_matches_variant,
)
from foundation_sec_server.reasoning_inference import (
    REASONING_SPLIT_END,
    REASONING_SPLIT_START,
    SPLIT_METHOD_CLOSED_TAG,
    SPLIT_METHOD_FALLBACK_H3,
    SPLIT_METHOD_SPLIT_FAILURE,
    ReasoningModelClient,
    answer_is_parseable,
    split_reasoning_answer,
)


class _FakeLlama:
    def __call__(self, prompt: str, **kwargs):
        self.last_prompt = prompt
        self.last_kwargs = kwargs
        return {
            "choices": [
                {
                    "text": (
                        "step one\n"
                        f"{REASONING_SPLIT_END}\n"
                        "Misconfiguration: SSH open to 0.0.0.0/0. Severity: high."
                    )
                }
            ],
            "usage": {"completion_tokens": 42},
        }

    def tokenize(self, data: bytes):
        return list(range(max(1, len(data) // 4)))


def test_assert_gguf_matches_variant_reasoning() -> None:
    assert_gguf_matches_variant("foundation-sec-8b-reasoning-q4_k_m.gguf", MODEL_VARIANT_REASONING)


def test_assert_gguf_rejects_instruct_for_reasoning_variant() -> None:
    try:
        assert_gguf_matches_variant("foundation-sec-1.1-8b-instruct-q4_k_m.gguf", MODEL_VARIANT_REASONING)
    except FileNotFoundError as exc:
        assert "variant mismatch" in str(exc)
    else:
        raise AssertionError("expected variant mismatch failure")


def test_split_reasoning_answer_after_template_injected_open_tag() -> None:
    raw = f"analyze ports\n{REASONING_SPLIT_END}\nUse restrictive ACLs."
    result = split_reasoning_answer(raw, token_counter=_FakeLlama())
    assert result.reasoning == "analyze ports"
    assert "restrictive ACLs" in result.answer
    assert result.split_method == SPLIT_METHOD_CLOSED_TAG
    assert not result.split_failure
    assert result.reasoning_token_count is not None
    assert result.answer_token_count is not None


def test_split_reasoning_answer_fallback_marker() -> None:
    raw = "internal monologue here\n\n### Security Audit Findings\n1. Issue"
    result = split_reasoning_answer(raw)
    assert result.reasoning == "internal monologue here"
    assert result.answer.startswith("### Security Audit Findings")
    assert result.split_method == SPLIT_METHOD_FALLBACK_H3


def test_split_failure_on_open_tag_without_close() -> None:
    raw = f"{REASONING_SPLIT_START}\nstill thinking"
    result = split_reasoning_answer(raw)
    assert result.split_failure
    assert result.split_method == SPLIT_METHOD_SPLIT_FAILURE
    assert result.answer == ""


def test_split_reasoning_answer_with_explicit_tags() -> None:
    raw = (
        f"{REASONING_SPLIT_START}thinking here{REASONING_SPLIT_END}\n"
        "Answer paragraph with remediation guidance."
    )
    result = split_reasoning_answer(raw)
    assert result.reasoning == "thinking here"
    assert "Answer paragraph" in result.answer


def test_reasoning_model_client_sampling_defaults() -> None:
    llm = _FakeLlama()
    client = ReasoningModelClient(llm)
    result = client.complete("review this firewall config")
    assert result.answer
    assert llm.last_kwargs["temperature"] == 0.3
    assert llm.last_kwargs["max_tokens"] == 8192
    assert REASONING_SPLIT_START in llm.last_prompt


def test_answer_is_parseable_prose() -> None:
    ok, reason = answer_is_parseable("SSH is exposed publicly. Restrict source addresses.")
    assert ok
    assert reason == "prose answer present"

    bad, reason = answer_is_parseable("://")
    assert not bad

    bad2, reason2 = answer_is_parseable("]" * 30)
    assert not bad2
    assert "degenerate" in reason2
