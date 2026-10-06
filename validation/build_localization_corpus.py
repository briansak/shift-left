#!/usr/bin/env python3
"""Assemble a CWE-89 localization corpus by fetching Celery at a pinned commit.

The upstream tree is not stored in this repository. The checkout is written
under validation/corpus/localization/, which is gitignored.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CELERY_REPO = "https://github.com/celery/celery.git"
CELERY_COMMIT = "918a740497a4ce883f37eb1a3e7c2a80dfcc8b7a"
SOURCE = ROOT / "validation" / "corpus" / "localization-source" / "celery"
CORPUS = ROOT / "validation" / "corpus" / "localization" / "celery-corpus"
SIDECAR = ROOT / "validation" / "corpus" / "localization" / "ground-truth.json"
GROUND_TRUTH_REL = "celery/backends/database/result_filter.py"


def _commit_sha(source: Path) -> str:
    return (
        subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True)
        .strip()
    )


def _copy_upstream(source: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        source,
        dest,
        ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc", ".pytest_cache"),
        dirs_exist_ok=False,
    )


def _write_result_filter_module(corpus: Path) -> None:
    module = corpus / "celery" / "backends" / "database" / "result_filter.py"
    module.write_text(
        '''"""Legacy result filtering helpers for the database result backend."""

from __future__ import annotations

import sqlite3
from typing import Any


def fetch_task_rows_by_name(
    database_path: str,
    task_name: str,
    *,
    worker_hostname: str,
) -> list[dict[str, Any]]:
    """Load task rows for a worker using the configured sqlite result store."""
    connection = sqlite3.connect(database_path)
    cursor = connection.cursor()
    query = (
        f"SELECT task_id, status, result, date_done FROM celery_taskmeta "
        f"WHERE name = '{task_name}' AND worker = '{worker_hostname}'"
    )
    cursor.execute(query)
    columns = [column[0] for column in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    connection.close()
    return rows
''',
        encoding="utf-8",
    )


def _scrub_answer_key_markers(corpus: Path) -> None:
    for path in corpus.rglob("README*"):
        text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = text.lower()
        if "cwe-89" in lowered or "sql injection" in lowered and "segment_lookup" in lowered:
            raise RuntimeError(f"Unexpected vulnerability marker in {path}")


def _corpus_stats(corpus: Path) -> dict[str, object]:
    py_files = sorted(path.relative_to(corpus).as_posix() for path in corpus.rglob("*.py"))
    total_bytes = sum(path.stat().st_size for path in corpus.rglob("*") if path.is_file())
    return {
        "python_file_count": len(py_files),
        "size_bytes": total_bytes,
        "size_mib": round(total_bytes / (1024 * 1024), 2),
    }


def _fetch_pinned_commit(dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--filter=blob:none", "--no-checkout", CELERY_REPO, str(dest)],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", CELERY_COMMIT],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", "--force", "FETCH_HEAD"],
        check=True,
    )


def build() -> dict[str, object]:
    _fetch_pinned_commit(SOURCE)
    commit_sha = _commit_sha(SOURCE)
    if commit_sha != CELERY_COMMIT:
        raise RuntimeError(f"Fetched {commit_sha}, expected pinned commit {CELERY_COMMIT}")
    _copy_upstream(SOURCE, CORPUS)
    _write_result_filter_module(CORPUS)
    _scrub_answer_key_markers(CORPUS)
    stats = _corpus_stats(CORPUS)

    payload = {
        "repo": "https://github.com/celery/celery",
        "commit_sha": commit_sha,
        "cwe": "CWE-89",
        "seeded_files": [GROUND_TRUTH_REL],
        "corpus_path": str(CORPUS.relative_to(ROOT)),
        **stats,
    }
    SIDECAR.parent.mkdir(parents=True, exist_ok=True)
    SIDECAR.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def main() -> int:
    payload = build()
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
