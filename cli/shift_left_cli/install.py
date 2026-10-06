"""Connected install — operator-initiated network access expected."""

from __future__ import annotations

import subprocess
from pathlib import Path


def connected_install(root: Path) -> None:
    print("Shift-Left connected install")
    print("Network egress is expected during this step (GitHub, registries, Hugging Face).")
    print("After install, runtime sovereignty requires all pipeline egress blocked.\n")

    _run(root, ["docker", "compose", "pull"])
    _run(root, ["docker", "compose", "build"])

    from shift_left_cli.stage_models import stage_models

    staging_messages = stage_models(root)
    for line in staging_messages:
        print(line)

    models_dir = root / "models" / "foundation-sec-q4_k_m"
    if not any(models_dir.glob("*.gguf")):
        print(
            "\nFoundation-Sec Q4_K_M GGUF still missing.\n"
            "  Repo: fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF\n"
            "  Run: ./scripts/download-foundation-sec-q4-model.sh"
        )

    print(
        "\nAntares is optional — not staged by default.\n"
        "  Run: ./shift-left install-antares (requires HF terms + HF_TOKEN)"
    )

    from shift_left_cli.sync_reference import sync_reference_data

    sync_reference_data(root)
    print("\nInstall complete. Run './shift-left up' for first-run bootstrap.")


def _run(root: Path, cmd: list[str]) -> None:
    print(f"$ {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=root)
