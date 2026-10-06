"""import-config and new-repo helpers."""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from shift_left.routing.globmatch import matches_any


def import_config_repo(root: Path, source: Path, *, config_path: Path | None = None) -> dict[str, list[str]]:
    cfg_path = config_path or root / "config" / "shift-left.yaml"
    raw = yaml.safe_load(cfg_path.read_text())
    globs = list((raw.get("routing") or {}).get("config_globs") or [])
    matched: list[str] = []
    skipped: list[str] = []

    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(source).as_posix()
        if matches_any(rel, globs):
            matched.append(rel)
        else:
            skipped.append(rel)

    return {"matched": matched, "skipped": skipped, "config_globs": globs}


def new_repo_scaffold(root: Path, name: str) -> str:
    from shift_left_cli.forgejo_bootstrap import _read_bootstrap_secret
    from shift_left_cli.forgejo_ci import ForgejoCiError, create_forgejo_review_repo

    token = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not token:
        token = _read_bootstrap_secret(root, "forgejo_token") or ""
    if not token:
        raise ForgejoCiError(
            "FORGEJO_TOKEN is not configured — run ./shift-left up (forgejo phase) first."
        )
    try:
        return create_forgejo_review_repo(root, name, forgejo_token=token)
    except ForgejoCiError as exc:
        raise RuntimeError(str(exc)) from exc


def shutil_copy(src: Path, dest: Path) -> None:
    dest.write_text(src.read_text())
