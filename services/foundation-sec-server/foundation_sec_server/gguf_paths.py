"""GGUF path resolution and manifest verification."""

from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import Path

from foundation_sec_server.model_profiles import (
    MODEL_VARIANT_INSTRUCT,
    MODEL_VARIANT_REASONING,
    assert_gguf_matches_variant,
    normalize_model_variant,
)
from shift_left_shared.weights import (
    VERIFIED_FOUNDATION_SEC_Q4_K_M,
    VERIFIED_FOUNDATION_SEC_Q8_0,
    VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M,
    load_prewarm_manifest,
    sha256_file,
)


def resolve_gguf_path(
    model_dir: Path,
    *,
    gguf_glob: str,
    quant_label: str,
    model_variant: str = MODEL_VARIANT_INSTRUCT,
) -> Path:
    if not model_dir.exists():
        raise FileNotFoundError(
            f"Foundation-Sec model directory missing: {model_dir}. "
            "Stage GGUF weights locally before starting."
        )
    matches = sorted(p for p in model_dir.iterdir() if p.is_file() and fnmatch(p.name, gguf_glob))
    if not matches:
        raise FileNotFoundError(
            f"No GGUF file matching glob {gguf_glob!r} under {model_dir} "
            f"(quant={quant_label}, variant={model_variant}). "
            f"Stage from {VERIFIED_FOUNDATION_SEC_Q8_0['hf_repo_id']}, "
            f"{VERIFIED_FOUNDATION_SEC_Q4_K_M['hf_repo_id']}, or "
            f"{VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M['hf_repo_id']} (see docs/licensing.md)."
        )
    if len(matches) > 1:
        raise FileNotFoundError(
            f"Multiple GGUF files match {gguf_glob!r} under {model_dir}: "
            f"{', '.join(p.name for p in matches)}. "
            "Set FOUNDATION_SEC_GGUF_GLOB to a unique pattern."
        )
    gguf = matches[0]
    assert_gguf_matches_variant(gguf.name, model_variant)
    return gguf


def verify_gguf_against_manifest(path: Path, manifest: dict, *, key: str) -> None:
    verified = {
        "foundation-sec": VERIFIED_FOUNDATION_SEC_Q8_0,
        "foundation-sec-low-memory": VERIFIED_FOUNDATION_SEC_Q4_K_M,
        "foundation-sec-reasoning": VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M,
    }.get(key, {})
    entry = (manifest.get("models") or {}).get(key) or {}
    expected_name = entry.get("gguf_filename") or verified.get("gguf_filename")
    expected_sha = entry.get("sha256") or verified.get("sha256")
    if expected_name and path.name != expected_name:
        raise FileNotFoundError(
            f"Resolved GGUF {path.name} does not match prewarm manifest ({expected_name})."
        )
    if expected_sha:
        actual = sha256_file(path)
        if actual != expected_sha:
            raise FileNotFoundError(
                f"GGUF SHA256 mismatch for {path.name}: expected {expected_sha}, got {actual}."
            )


def gguf_settings_from_env() -> tuple[Path, str, str, bool, str, str]:
    """Return model_dir, gguf_glob, quant_label, use_low_memory, manifest_key, model_variant."""
    model_variant = normalize_model_variant(os.environ.get("FOUNDATION_SEC_MODEL_VARIANT"))
    model_dir = Path(os.environ.get("FOUNDATION_SEC_MODEL_PATH", "/models/foundation-sec"))

    if model_variant == MODEL_VARIANT_REASONING:
        meta = VERIFIED_FOUNDATION_SEC_REASONING_Q4_K_M
        gguf_glob = os.environ.get("FOUNDATION_SEC_GGUF_GLOB", meta["gguf_glob"]).strip()
        quant_label = os.environ.get("FOUNDATION_SEC_QUANT_LABEL", "reasoning-q4_k_m").strip()
        manifest_key = os.environ.get("FOUNDATION_SEC_PREWARM_MANIFEST_KEY", meta["manifest_key"])
        if not gguf_glob:
            raise RuntimeError(
                "FOUNDATION_SEC_MODEL_VARIANT=reasoning requires FOUNDATION_SEC_GGUF_GLOB "
                f"(default: {meta['gguf_glob']})."
            )
        return model_dir, gguf_glob, quant_label, False, manifest_key, model_variant

    use_low = os.environ.get("FOUNDATION_SEC_LOW_MEMORY", "").lower() in {"1", "true", "yes"}
    if use_low:
        gguf_glob = os.environ.get(
            "FOUNDATION_SEC_LOW_MEMORY_GGUF_GLOB",
            VERIFIED_FOUNDATION_SEC_Q4_K_M["gguf_glob"],
        ).strip()
        quant_label = os.environ.get("FOUNDATION_SEC_LOW_MEMORY_QUANT_LABEL", "low-memory").strip()
        manifest_key = os.environ.get(
            "FOUNDATION_SEC_PREWARM_MANIFEST_KEY",
            VERIFIED_FOUNDATION_SEC_Q4_K_M["manifest_key"],
        )
        if not gguf_glob:
            raise RuntimeError(
                "FOUNDATION_SEC_LOW_MEMORY=true requires FOUNDATION_SEC_LOW_MEMORY_GGUF_GLOB "
                f"(default: {VERIFIED_FOUNDATION_SEC_Q4_K_M['gguf_glob']})."
            )
    else:
        gguf_glob = os.environ.get(
            "FOUNDATION_SEC_GGUF_GLOB",
            VERIFIED_FOUNDATION_SEC_Q8_0["gguf_glob"],
        ).strip()
        quant_label = os.environ.get("FOUNDATION_SEC_QUANT_LABEL", "default").strip()
        manifest_key = os.environ.get(
            "FOUNDATION_SEC_PREWARM_MANIFEST_KEY",
            VERIFIED_FOUNDATION_SEC_Q8_0["manifest_key"],
        )
        if not gguf_glob:
            raise RuntimeError(
                "FOUNDATION_SEC_GGUF_GLOB must be set explicitly "
                f"(default: {VERIFIED_FOUNDATION_SEC_Q8_0['gguf_glob']})."
            )
    return model_dir, gguf_glob, quant_label, use_low, manifest_key, model_variant
