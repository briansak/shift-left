"""Optional Antares install (HF terms + token required)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import yaml


def install_antares(root: Path) -> None:
    if not _token_present():
        raise SystemExit(
            "Antares is optional and gated on Hugging Face.\n"
            "  1. Accept terms at https://huggingface.co/fdtn-ai/antares-1b\n"
            "  2. Set HF_TOKEN in .env\n"
            "  3. Re-run: ./shift-left install-antares"
        )

    script = root / "scripts" / "download-antares-model.sh"
    if not script.is_file():
        raise SystemExit(f"Missing {script}")
    print("Downloading Antares weights (operator-initiated egress)…")
    from shift_left_cli.script_util import run_bash_script

    env = os.environ.copy()
    venv_bin = root / ".venv" / "bin"
    if venv_bin.is_dir():
        env["PATH"] = f"{venv_bin}{os.pathsep}{env.get('PATH', '')}"
    run_bash_script(root, script, env=env)

    cfg_path = root / "config" / "shift-left.yaml"
    if cfg_path.exists():
        raw = yaml.safe_load(cfg_path.read_text())
        antares = raw.setdefault("models", {}).setdefault("antares", {})
        antares["installed"] = True
        antares["enabled"] = True
        antares["local_path"] = "models/1b"
        antares["hf_repo_id"] = "fdtn-ai/antares-1b"
        triage = raw.setdefault("antares_triage", {})
        triage["installed"] = True
        triage["enabled"] = True
        cfg_path.write_text(yaml.safe_dump(raw, sort_keys=False))

    from shift_left_cli.model_packages import ensure_antares_server_package

    ensure_antares_server_package(root)
    print("Antares staged. Start with: ./shift-left model start antares-server")


def _token_present() -> bool:
    return bool(
        os.environ.get("HF_TOKEN")
        or os.environ.get("HUGGING_FACE_HUB_TOKEN")
        or os.environ.get("HUGGINGFACE_HUB_TOKEN")
    )
