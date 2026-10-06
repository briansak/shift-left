"""Model staging helpers for connected install."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def stage_models(root: Path) -> list[str]:
    """
    Invoke operator download scripts when weights are missing.

    Default install stages Foundation-Sec Q4_K_M only — Antares is optional.
    """
    messages: list[str] = []
    env = os.environ.copy()

    q4_dir = root / "models" / "foundation-sec-q4_k_m"
    if not any(q4_dir.glob("*.gguf")):
        messages.extend(_run_download(root, "download-foundation-sec-q4-model.sh", env))

    messages.append(
        "Antares is optional (advisory triage only). Install with: ./shift-left install-antares"
    )
    return messages


def _run_download(root: Path, script_name: str, env: dict[str, str]) -> list[str]:
    script = root / "scripts" / script_name
    if not script.is_file():
        return [f"Missing script {script} — stage weights manually."]

    if script_name.startswith("download-antares") and not _token_present(env):
        return [
            "Antares weights missing.",
            "  1. Accept terms at https://huggingface.co/fdtn-ai/antares-1b",
            "  2. Set HF_TOKEN in .env",
            "  3. Run ./scripts/download-antares-model.sh",
        ]

    try:
        from shift_left_cli.script_util import run_bash_script_capture

        proc = run_bash_script_capture(root, script, env=env)
    except OSError as exc:
        return [f"Failed to run {script_name}: {exc}"]

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if "HF_TOKEN" in detail or "401" in detail or "403" in detail or "gated" in detail.lower():
            return [
                f"{script_name} failed — Hugging Face authentication or gated access.",
                "  Accept the model agreement and set HF_TOKEN, then re-run the script.",
            ]
        return [f"{script_name} failed:", detail or f"exit code {proc.returncode}"]

    return [f"{script_name} completed successfully."]


def _token_present(env: dict[str, str]) -> bool:
    return bool(
        env.get("HF_TOKEN") or env.get("HUGGING_FACE_HUB_TOKEN") or env.get("HUGGINGFACE_HUB_TOKEN")
    )
