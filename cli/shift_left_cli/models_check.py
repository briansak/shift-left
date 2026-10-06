"""Detect locally staged model weights before operator-initiated downloads."""

from __future__ import annotations

import fnmatch
import shutil
from dataclasses import dataclass
from pathlib import Path

from shift_left_shared.weights import VERIFIED_FOUNDATION_SEC_Q4_K_M, VERIFIED_FOUNDATION_SEC_Q8_0


@dataclass(frozen=True)
class ModelStagingStatus:
    foundation_sec_q4_path: Path | None
    foundation_sec_q8_path: Path | None
    use_low_memory: bool
    repair_actions: tuple[str, ...]

    @property
    def active_gguf_path(self) -> Path | None:
        if self.foundation_sec_q4_path is not None:
            return self.foundation_sec_q4_path
        return self.foundation_sec_q8_path

    @property
    def foundation_sec_ready(self) -> bool:
        return self.active_gguf_path is not None and self.active_gguf_path.is_file()

    @property
    def needs_foundation_sec_download(self) -> bool:
        return not self.foundation_sec_ready


def inspect_model_staging(root: Path) -> ModelStagingStatus:
    repairs = tuple(repair_nested_models_dir(root))
    q4_path = find_gguf_weight(root, VERIFIED_FOUNDATION_SEC_Q4_K_M)
    q8_path = find_gguf_weight(root, VERIFIED_FOUNDATION_SEC_Q8_0)
    return ModelStagingStatus(
        foundation_sec_q4_path=q4_path,
        foundation_sec_q8_path=q8_path,
        use_low_memory=q4_path is not None,
        repair_actions=repairs,
    )


def repair_nested_models_dir(root: Path) -> list[str]:
    """Fix common restore mistake: copying the whole models/ tree into models/models/."""
    nested = root / "models" / "models"
    if not nested.is_dir():
        return []

    actions: list[str] = []
    for item in sorted(nested.iterdir()):
        if item.name.startswith("."):
            continue
        dest = root / "models" / item.name
        if dest.exists():
            continue
        shutil.move(str(item), str(dest))
        actions.append(f"Moved {item.relative_to(root)} → {dest.relative_to(root)}")

    nested_manifest = nested / ".prewarm-manifest.json"
    dest_manifest = root / "models" / ".prewarm-manifest.json"
    if nested_manifest.is_file() and not dest_manifest.exists():
        shutil.move(str(nested_manifest), str(dest_manifest))
        actions.append(f"Moved {nested_manifest.relative_to(root)} → {dest_manifest.relative_to(root)}")

    try:
        nested.rmdir()
    except OSError:
        pass

    return actions


def find_foundation_sec_q4_gguf(root: Path) -> Path | None:
    return find_gguf_weight(root, VERIFIED_FOUNDATION_SEC_Q4_K_M)


def find_foundation_sec_q8_gguf(root: Path) -> Path | None:
    return find_gguf_weight(root, VERIFIED_FOUNDATION_SEC_Q8_0)


def find_gguf_weight(root: Path, meta: dict[str, str]) -> Path | None:
    expected_dir = root / meta["local_path_default"]
    expected_file = expected_dir / meta["gguf_filename"]
    if expected_file.is_file() and expected_file.stat().st_size > 0:
        return expected_file

    search_roots = [
        root / "models",
        root / "models" / "models",
    ]
    for base in search_roots:
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.gguf")):
            if path.stat().st_size <= 0:
                continue
            if _matches_gguf_name(path.name, meta["gguf_filename"], meta["gguf_glob"]):
                return path
    return None


def _matches_gguf_name(name: str, expected: str, glob_pattern: str) -> bool:
    if name == expected:
        return True
    return fnmatch.fnmatch(name, glob_pattern)


def print_model_staging_report(root: Path, status: ModelStagingStatus | None = None) -> ModelStagingStatus:
    status = status or inspect_model_staging(root)
    for action in status.repair_actions:
        print(f"Models: {action}")

    if status.foundation_sec_q4_path is not None:
        rel = status.foundation_sec_q4_path.relative_to(root)
        print(f"Models: Foundation-Sec Q4_K_M present ({rel}) — download will be skipped")
        return status

    if status.foundation_sec_q8_path is not None:
        rel = status.foundation_sec_q8_path.relative_to(root)
        print(
            f"Models: Foundation-Sec Q8_0 present ({rel}) — download will be skipped\n"
            "  Using Q8_0 profile (~8.5 GB+ peak RAM). Q4_K_M is the default when both are available."
        )
        return status

    q4_dest = root / VERIFIED_FOUNDATION_SEC_Q4_K_M["local_path_default"] / VERIFIED_FOUNDATION_SEC_Q4_K_M["gguf_filename"]
    print(
        "Models: no Foundation-Sec GGUF found — will download Q4_K_M during fetch\n"
        f"  Expected: {q4_dest.relative_to(root)}\n"
        f"  Or restore your backup under models/ (not models/models/) and re-run ./shift-left up"
    )
    return status
