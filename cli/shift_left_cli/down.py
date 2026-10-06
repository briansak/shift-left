"""./shift-left down"""

from __future__ import annotations

from pathlib import Path

from shift_left_cli.stack import stop_compose_stack
from shift_left_cli.up import load_dotenv


def operator_down(root: Path) -> None:
    load_dotenv(root)
    from shift_left.system.supervisor import stop_service

    for service in ("foundation-sec-server", "antares-server"):
        stop_service(root, service)
    stop_compose_stack(root)
    print("Shift-Left stack stopped.")
