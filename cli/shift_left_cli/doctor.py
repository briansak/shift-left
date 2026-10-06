"""./shift-left doctor"""

from __future__ import annotations

from pathlib import Path

from shift_left_cli.compose_util import detect_compose
from shift_left_cli.preflight import detect_platform, run_preflight
from shift_left_cli.up import load_dotenv


def operator_doctor(root: Path) -> None:
    load_dotenv(root)
    print("Shift-Left doctor\n")
    try:
        run_preflight(root)
        print("Preflight: OK")
    except Exception as exc:  # noqa: BLE001
        print(f"Preflight: FAIL — {exc}")

    try:
        from shift_left_cli.preflight import ensure_docker_daemon

        ensure_docker_daemon(root)
    except Exception as exc:  # noqa: BLE001
        print(f"Docker daemon: FAIL — {exc}")

    try:
        compose = detect_compose(root)
        print(f"Compose CLI: {compose.form}")
    except Exception as exc:  # noqa: BLE001
        print(f"Compose CLI: FAIL — {exc}")

    platform = detect_platform()
    print(f"Platform: {platform}")

    config = root / "config" / "shift-left.yaml"
    print(f"Config: {'present' if config.exists() else 'missing — run ./shift-left up'}")
    env = root / ".env"
    print(f".env: {'present' if env.exists() else 'missing'}")

    if config.exists() and env.exists():
        print("\nSuggested fix: ./shift-left up  (resumes incomplete phases)")
