"""Resolve staged model weight directories — single source of truth."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from shift_left_shared.weights import VERIFIED_ANTARES_1B, VERIFIED_ANTARES_350M


def resolve_antares_weights_dir(root: Path, antares_cfg: dict[str, Any] | Any) -> Path:
    """Resolve staged Antares weights, preferring configured path then 1B minimum layout."""
    if hasattr(antares_cfg, "model_dump"):
        antares_cfg = antares_cfg.model_dump()
    rel = str(antares_cfg.get("local_path") or VERIFIED_ANTARES_1B["local_path_default"])
    candidate = (root / rel).resolve()
    if (candidate / "config.json").is_file():
        return candidate
    for fallback_rel in (
        VERIFIED_ANTARES_1B["local_path_default"],
        VERIFIED_ANTARES_350M["local_path_default"],
    ):
        fallback = (root / fallback_rel).resolve()
        if (fallback / "config.json").is_file():
            return fallback
    return candidate
