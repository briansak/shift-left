"""Foundation-Sec model variant profiles (instruct vs reasoning)."""

from __future__ import annotations

MODEL_VARIANT_INSTRUCT = "instruct"
MODEL_VARIANT_REASONING = "reasoning"

REASONING_N_CTX_DEFAULT = 16384
REASONING_MAX_TOKENS_DEFAULT = 8192
INSTRUCT_N_CTX_DEFAULT = 4096

REASONING_SPLIT_START = "<think>"
REASONING_SPLIT_END = "</think>"


def normalize_model_variant(raw: str | None) -> str:
    value = (raw or MODEL_VARIANT_INSTRUCT).strip().lower()
    if value not in {MODEL_VARIANT_INSTRUCT, MODEL_VARIANT_REASONING}:
        raise ValueError(
            f"Unsupported Foundation-Sec model_variant={raw!r}; "
            f"expected {MODEL_VARIANT_INSTRUCT!r} or {MODEL_VARIANT_REASONING!r}."
        )
    return value


def gguf_filename_matches_variant(filename: str, variant: str) -> bool:
    lowered = filename.lower()
    if variant == MODEL_VARIANT_REASONING:
        return "reasoning" in lowered and "instruct" not in lowered
    return "instruct" in lowered and "reasoning" not in lowered


def assert_gguf_matches_variant(filename: str, variant: str) -> None:
    """Hard-fail when the resolved GGUF does not match the requested variant."""
    if gguf_filename_matches_variant(filename, variant):
        return
    raise FileNotFoundError(
        f"GGUF variant mismatch: requested model_variant={variant!r} but "
        f"resolved file {filename!r}. "
        "Stage the correct weights directory or set FOUNDATION_SEC_MODEL_VARIANT."
    )
