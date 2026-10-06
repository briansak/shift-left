"""Host-native model server control (./shift-left model …)."""

from __future__ import annotations

from pathlib import Path

SERVICE_ALIASES = {
    "foundation-sec-server": "foundation-sec-server",
    "foundation-sec": "foundation-sec-server",
    "antares-server": "antares-server",
    "antares": "antares-server",
}


def operator_model(root: Path, action: str, service: str) -> None:
    canonical = SERVICE_ALIASES.get(service.replace("_", "-"), service.replace("_", "-"))
    if canonical not in {"foundation-sec-server", "antares-server"}:
        raise SystemExit(f"Unknown model service: {service}")

    from shift_left.system.supervisor import (
        is_running,
        restart_service,
        start_service,
        stop_service,
    )
    from shift_left_cli.model_packages import (
        ensure_antares_server_package,
        ensure_foundation_sec_server_package,
    )

    if action in {"start", "restart"}:
        if canonical == "antares-server":
            ensure_antares_server_package(root)
        elif canonical == "foundation-sec-server":
            ensure_foundation_sec_server_package(root)

    if action == "start":
        info = start_service(root, canonical)
        if not is_running(root, canonical):
            log_path = info.get("log_path", "")
            tail = ""
            if log_path:
                try:
                    lines = Path(log_path).read_text(encoding="utf-8").splitlines()
                    tail = "\n".join(lines[-12:])
                except OSError:
                    pass
            raise SystemExit(
                f"{canonical} exited immediately after start.\n"
                f"Log: {log_path}\n"
                f"{tail or '(empty log)'}"
            )
        print(f"Started {canonical} (PID {info['pid']}) — log {info['log_path']}")
    elif action == "stop":
        stop_service(root, canonical)
        print(f"Stopped {canonical}.")
    elif action == "restart":
        info = restart_service(root, canonical)
        if not is_running(root, canonical):
            log_path = info.get("log_path", "")
            tail = ""
            if log_path:
                try:
                    lines = Path(log_path).read_text(encoding="utf-8").splitlines()
                    tail = "\n".join(lines[-12:])
                except OSError:
                    pass
            raise SystemExit(
                f"{canonical} exited immediately after restart.\n"
                f"Log: {log_path}\n"
                f"{tail or '(empty log)'}"
            )
        print(f"Restarted {canonical} (PID {info['pid']}).")
    else:
        raise SystemExit(f"Unknown action: {action}")
