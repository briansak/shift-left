"""Detect and cache the available Docker Compose CLI invocation form."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from shutil import which
from typing import Any

from shift_left.config import resolve_repo_root


@dataclass(frozen=True)
class ComposeCliReport:
    argv_prefix: tuple[str, ...]
    form: str
    available: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "form": self.form,
            "argv_prefix": list(self.argv_prefix),
            "available": self.available,
            "error": self.error,
        }


def _parse_override(value: str | None) -> tuple[str, ...] | None:
    if not value:
        return None
    normalized = value.strip().lower()
    if normalized in {"docker compose", "docker-compose"}:
        return ("docker", "compose") if normalized == "docker compose" else ("docker-compose",)
    raise ValueError(
        f"Invalid orchestrator.compose_command {value!r} — use 'docker compose' or 'docker-compose'."
    )


def _probe_form(argv_prefix: tuple[str, ...]) -> bool:
    if argv_prefix == ("docker", "compose"):
        if which("docker") is None:
            return False
    elif argv_prefix == ("docker-compose",):
        if which("docker-compose") is None:
            return False
    else:
        return False
    cmd = [*argv_prefix, "version"]
    result = subprocess.run(
        cmd,
        cwd=str(resolve_repo_root()),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return result.returncode == 0


def detect_compose_cli(*, config_override: str | None = None) -> ComposeCliReport:
    """
    Probe compose CLI forms in order: ``docker compose``, then ``docker-compose``.

    Config override ``orchestrator.compose_command`` or env
    ``SHIFT_LEFT_COMPOSE_COMMAND`` may force a form.
    """
    env_override = os.environ.get("SHIFT_LEFT_COMPOSE_COMMAND", "").strip() or None
    override = _parse_override(config_override) or _parse_override(env_override)
    if override is not None:
        if _probe_form(override):
            form = "docker compose" if override == ("docker", "compose") else "docker-compose"
            return ComposeCliReport(argv_prefix=override, form=form, available=True)
        form = "docker compose" if override == ("docker", "compose") else "docker-compose"
        return ComposeCliReport(
            argv_prefix=override,
            form=form,
            available=False,
            error=(
                f"Configured compose command {form!r} is not available or failed "
                f"'{form} version'."
            ),
        )

    for argv_prefix, form in (
        (("docker", "compose"), "docker compose"),
        (("docker-compose",), "docker-compose"),
    ):
        if _probe_form(argv_prefix):
            return ComposeCliReport(argv_prefix=argv_prefix, form=form, available=True)

    return ComposeCliReport(
        argv_prefix=(),
        form="unavailable",
        available=False,
        error=(
            "Neither 'docker compose' nor 'docker-compose' is available. "
            "Install the Compose plugin or standalone binary, or set orchestrator.compose_command."
        ),
    )


@lru_cache(maxsize=1)
def cached_compose_cli(config_override: str | None = None) -> ComposeCliReport:
    return detect_compose_cli(config_override=config_override)


def compose_argv_prefix(*, config_override: str | None = None) -> tuple[str, ...]:
    report = cached_compose_cli(config_override)
    if not report.available:
        raise RuntimeError(report.error or "Docker Compose CLI unavailable.")
    return report.argv_prefix


def invalidate_compose_cli_cache() -> None:
    cached_compose_cli.cache_clear()
