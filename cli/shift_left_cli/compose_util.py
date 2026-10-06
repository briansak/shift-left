"""Compose CLI detection for operator commands."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ComposeCli:
    argv_prefix: tuple[str, ...]
    form: str

    def cmd(self, *parts: str) -> list[str]:
        return [*self.argv_prefix, *parts]


def detect_compose(root: Path, *, override: str | None = None) -> ComposeCli:
    env_override = os.environ.get("SHIFT_LEFT_COMPOSE_COMMAND", "").strip() or None
    chosen = override or env_override
    if chosen:
        normalized = chosen.strip().lower()
        if normalized == "docker compose":
            prefix = ("docker", "compose")
        elif normalized == "docker-compose":
            prefix = ("docker-compose",)
        else:
            raise RuntimeError(f"Invalid compose override {chosen!r}")
        _verify(prefix, root)
        return ComposeCli(argv_prefix=prefix, form=normalized)

    for prefix, form in (
        (("docker", "compose"), "docker compose"),
        (("docker-compose",), "docker-compose"),
    ):
        if _probe(prefix, root):
            return ComposeCli(argv_prefix=prefix, form=form)

    raise RuntimeError(
        "Neither 'docker compose' nor 'docker-compose' is available. "
        "Install Colima/Docker and the Compose plugin, or set SHIFT_LEFT_COMPOSE_COMMAND."
    )


def _probe(prefix: tuple[str, ...], root: Path) -> bool:
    try:
        _verify(prefix, root)
        return True
    except RuntimeError:
        return False


def _verify(prefix: tuple[str, ...], root: Path) -> None:
    result = subprocess.run(
        [*prefix, "version"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        form = "docker compose" if prefix == ("docker", "compose") else "docker-compose"
        raise RuntimeError(f"{form} version failed: {detail or result.returncode}")
