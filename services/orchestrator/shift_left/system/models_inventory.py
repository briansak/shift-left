"""Local model weight inventory — staged vs configured."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shift_left.config import AppConfig, resolve_repo_relative_path


def _glob_matches(directory: Path, pattern: str) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(directory.glob(pattern))


def foundation_sec_inventory(
    config: AppConfig,
    *,
    prereq_checks: list[dict[str, Any]] | None = None,
) -> dict:
    fs = config.models.foundation_sec

    q8_dir = resolve_repo_relative_path(fs.local_path)
    q4_dir = resolve_repo_relative_path(fs.local_path_low_memory)
    reasoning_dir = resolve_repo_relative_path(fs.local_path_reasoning)

    q8_files = _glob_matches(q8_dir, fs.gguf_glob)
    q4_files = _glob_matches(q4_dir, fs.gguf_glob_low_memory)
    reasoning_files = _glob_matches(reasoning_dir, fs.gguf_glob_reasoning)

    if fs.model_variant == "reasoning":
        active_quant = fs.quant_label_reasoning
        active_glob = fs.gguf_glob_reasoning
        active_dir = reasoning_dir
        active_files = reasoning_files
        configured_profile = "Reasoning Q4_K_M (n_ctx=16384)"
        recommended_profile = "Reasoning Q4_K_M at n_ctx=16384 (~4.9 GB weights + KV cache)"
    else:
        active_quant = fs.quant_label_low_memory if fs.use_low_memory else fs.quant_label
        active_glob = fs.gguf_glob_low_memory if fs.use_low_memory else fs.gguf_glob
        active_dir = q4_dir if fs.use_low_memory else q8_dir
        active_files = q4_files if fs.use_low_memory else q8_files
        configured_profile = "Q4_K_M (low-memory)" if fs.use_low_memory else "Q8_0 (default)"
        recommended_profile = "Q4_K_M at n_ctx=4096 (~4–5 GB peak on 24 GB host)"

    measured_note = (
        "Measured peak ~9.3 GB RAM + ~11 GB swap with Q8_0 at n_ctx=8192 on this 24 GB host."
        if fs.model_variant != "reasoning"
        else (
            "Reasoning Q4_K_M weights ~4.9 GB; KV cache at n_ctx=16384 is material on a 24 GB host — "
            "run validation/reasoning_phase1_smoke.py for measured RSS/swap."
        )
    )

    q8_staged = bool(q8_files)
    q4_staged = bool(q4_files)
    reasoning_staged = bool(reasoning_files)
    active_profile_staged = bool(active_files)
    staging_verified_via: str | None = "disk" if active_profile_staged else None

    if prereq_checks:
        by_id = {item["id"]: item for item in prereq_checks}
        server = by_id.get("foundation_sec_server", {})
        weights = by_id.get("foundation_sec_weights", {})
        runtime_confirmed = False
        if server.get("ok"):
            runtime = (server.get("details") or {}).get("runtime") or {}
            if runtime.get("gguf_file") or runtime.get("loaded"):
                runtime_confirmed = True
        weights_details = weights.get("details") or {}
        if weights.get("ok") and weights_details.get("verified_via") == "runtime_health":
            runtime_confirmed = True
        if runtime_confirmed:
            if fs.model_variant == "reasoning":
                reasoning_staged = True
            elif fs.use_low_memory:
                q4_staged = True
            else:
                q8_staged = True
            active_profile_staged = True
            staging_verified_via = "runtime_health"

    configured_n_ctx = (
        fs.max_context_tokens_reasoning
        if fs.model_variant == "reasoning"
        else fs.max_context_tokens
    )

    return {
        "configured_model_variant": fs.model_variant,
        "configured_use_low_memory": fs.use_low_memory,
        "configured_quant_label": active_quant,
        "configured_gguf_glob": active_glob,
        "configured_n_ctx": configured_n_ctx,
        "configured_profile": configured_profile,
        "recommended_profile": recommended_profile,
        "measured_note": measured_note,
        "q8_0_staged": q8_staged,
        "q8_0_path": str(q8_dir),
        "q8_0_files": [item.name for item in q8_files],
        "q4_k_m_staged": q4_staged,
        "q4_k_m_path": str(q4_dir),
        "q4_k_m_files": [item.name for item in q4_files],
        "reasoning_q4_k_m_staged": reasoning_staged,
        "reasoning_q4_k_m_path": str(reasoning_dir),
        "reasoning_q4_k_m_files": [item.name for item in reasoning_files],
        "active_weights_present": active_profile_staged,
        "active_profile_staged": active_profile_staged,
        "staging_verified_via": staging_verified_via,
        "config_applied": active_profile_staged,
        "staging_gap": (
            "Reasoning Q4_K_M weights are not staged locally — model_variant=reasoning would fail "
            "until models/foundation-sec-reasoning-q4_k_m/ is populated."
            if fs.model_variant == "reasoning" and not reasoning_staged
            else (
                "Q4_K_M weights are not staged locally — use_low_memory=true would fail until "
                "models/foundation-sec-q4_k_m/ is populated."
                if fs.model_variant != "reasoning" and fs.use_low_memory and not q4_staged
                else None
            )
        ),
    }
