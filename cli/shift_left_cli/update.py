"""Operator-initiated updates — never automatic, never background."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from shift_left_cli.compose_util import detect_compose
from shift_left_cli.preflight import PreflightError, ensure_docker_daemon


def operator_update(root: Path) -> None:
    print("Shift-Left operator update")
    print("This command pulls project updates and container images when you run it.")
    print("There are no background update checks.\n")

    # TODO: pin release channel / version verification against GitHub releases
    try:
        _run(root, ["git", "pull", "--ff-only"])
        ensure_docker_daemon(root, resume="./shift-left update")
        from shift_left_cli.forgejo_config import (
            cleanup_stale_forgejo_run_containers,
            ensure_forgejo_data_permissions,
        )

        cleanup_stale_forgejo_run_containers(root)
        ensure_forgejo_data_permissions(root)
        compose = detect_compose(root)
        print(f"Compose CLI: {compose.form}")
        _run(root, compose.cmd("pull"))
        _run(root, compose.cmd("build"))
    except PreflightError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from None
    except subprocess.CalledProcessError as exc:
        print(
            f"\nUpdate failed (exit {exc.returncode}): {' '.join(exc.cmd)}",
            file=sys.stderr,
        )
        print("Fix the error above, then re-run: ./shift-left update", file=sys.stderr)
        raise SystemExit(exc.returncode) from None

    print(f"\nUpdate complete. Restart services: {compose.form} up -d")


def update_from_bundle(root: Path, bundle: Path) -> None:
    """Offline update path using a refreshed bundle."""
    from shift_left_cli.bundle import bundle_install

    bundle_install(root, bundle)


def _run(root: Path, cmd: list[str]) -> None:
    print(f"$ {' '.join(cmd)}")
    subprocess.check_call(cmd, cwd=root)
