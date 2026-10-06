"""Shared report metadata for Foundation-Sec-8B-Reasoning eval artifacts."""

from __future__ import annotations

from typing import Any

from foundation_sec_server.model_profiles import (
    MODEL_VARIANT_REASONING,
    REASONING_MAX_TOKENS_DEFAULT,
    REASONING_N_CTX_DEFAULT,
)

REASONING_QUANT = "Q4_K_M"
REASONING_COOKBOOK_THRESHOLD = 0.80
REASONING_INFERENCE_PATH = "chat_template"
REASONING_SCORING_SURFACE = "whole_completion"


def reasoning_run_stamp(
    *,
    max_tokens: int = REASONING_MAX_TOKENS_DEFAULT,
    threshold: float | None = None,
    scoring_surface: str = REASONING_SCORING_SURFACE,
    inference_path: str = REASONING_INFERENCE_PATH,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model_variant": MODEL_VARIANT_REASONING,
        "quant": REASONING_QUANT,
        "n_ctx": REASONING_N_CTX_DEFAULT,
        "max_tokens": max_tokens,
        "scoring_surface": scoring_surface,
        "inference_path": inference_path,
    }
    if threshold is not None:
        payload["threshold"] = threshold
    if extra:
        payload.update(extra)
    return payload
