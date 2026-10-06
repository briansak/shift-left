"""Deterministic repo profiler tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from shift_left.profiler.profile import profile_repository
from shift_left.profiler.surfaces import scan_import_surfaces


def _init_repo(path: Path, files: dict[str, str]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)
    for rel, content in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=path, check=True)


def test_repo_without_database_has_no_cwe_89(tmp_path: Path) -> None:
    repo = tmp_path / "plain"
    _init_repo(repo, {"app/main.py": "print('hello')\n"})
    result = profile_repository(repo)
    assert "CWE-89" not in {item.cwe_id for item in result.suggestions}


def test_repo_with_sqlalchemy_raw_sql_yields_cwe_89_direct(tmp_path: Path) -> None:
    repo = tmp_path / "sql"
    _init_repo(
        repo,
        {
            "requirements.txt": "sqlalchemy\n",
            "app/db.py": (
                "import sqlalchemy\n"
                'cursor.execute(f"SELECT {user_id} FROM users")\n'
            ),
        },
    )
    result = profile_repository(repo)
    match = next((item for item in result.suggestions if item.cwe_id == "CWE-89"), None)
    assert match is not None
    assert match.relevance_tier == "direct"
    assert match.evidence


def test_deferred_sql_multiline_fstring_then_execute_is_direct(tmp_path: Path) -> None:
    repo = tmp_path / "multiline"
    _init_repo(
        repo,
        {
            "app/result_filter.py": (
                "import sqlite3\n"
                "def fetch(task_name, worker_hostname):\n"
                "    connection = sqlite3.connect('x.db')\n"
                "    cursor = connection.cursor()\n"
                "    query = (\n"
                '        f"SELECT task_id FROM celery_taskmeta "\n'
                '        f"WHERE name = \'{task_name}\' AND worker = \'{worker_hostname}\'"\n'
                "    )\n"
                "    cursor.execute(query)\n"
                "    return cursor.fetchall()\n"
            ),
        },
    )
    result = profile_repository(repo)
    match = next((item for item in result.suggestions if item.cwe_id == "CWE-89"), None)
    assert match is not None
    assert match.relevance_tier == "direct"
    assert any("result_filter.py" in (ev.file or "") for ev in match.evidence)


def test_parameterized_execute_is_not_direct_sql_callsite(tmp_path: Path) -> None:
    repo = tmp_path / "safe"
    _init_repo(
        repo,
        {
            "app/db.py": (
                "import sqlite3\n"
                "def fetch(user_id):\n"
                "    cursor = sqlite3.connect('x.db').cursor()\n"
                '    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))\n'
                "    return cursor.fetchall()\n"
            ),
        },
    )
    from shift_left.profiler.surfaces import scan_callsite_surfaces

    callsites = scan_callsite_surfaces(repo)
    raw_sql = [item for item in callsites if item.surface == "raw_sql_callsite"]
    assert not raw_sql
    result = profile_repository(repo)
    match = next((item for item in result.suggestions if item.cwe_id == "CWE-89"), None)
    if match is not None:
        assert match.relevance_tier != "direct"


def test_authz_api_ignores_docstrings_comments_and_string_literals(tmp_path: Path) -> None:
    repo = tmp_path / "authz-fp"
    _init_repo(
        repo,
        {
            "app/redis.py": (
                "# Only Redis supports username/password authentication.\n"
                "value = 'permission granted'\n"
            ),
            "app/mongo.py": (
                'def database():\n'
                '    """performs authentication if necessary."""\n'
                "    return None\n"
            ),
            "app/license.py": (
                '"""Permission is hereby granted, free of charge."""\n'
                "x = 1\n"
            ),
        },
    )
    hits = [item for item in scan_import_surfaces(repo) if item.surface == "authz_api"]
    assert hits == []


def test_test_only_imports_do_not_surface_cwe_suggestions(tmp_path: Path) -> None:
    repo = tmp_path / "tests-only"
    _init_repo(
        repo,
        {
            "t/unit/fixups/test_django.py": "import django\n",
            "t/integration/test_security.py": "from cryptography import x509\n",
        },
    )
    result = profile_repository(repo)
    assert "CWE-79" not in {item.cwe_id for item in result.suggestions}
    assert "CWE-798" not in {item.cwe_id for item in result.suggestions}


def test_celery_corpus_cwe_89_direct_with_result_filter_evidence() -> None:
    corpus = Path(__file__).resolve().parents[3] / "validation" / "corpus" / "localization" / "celery-corpus"
    if not corpus.is_dir():
        pytest.skip(
            "Celery localization corpus is not in the tree. "
            "Rebuild it locally with: python validation/build_localization_corpus.py"
        )
    result = profile_repository(corpus)
    match = next((item for item in result.suggestions if item.cwe_id == "CWE-89"), None)
    assert match is not None
    assert match.relevance_tier == "direct"
    assert any(
        ev.kind == "callsite"
        and ev.surface == "raw_sql_callsite"
        and ev.file == "celery/backends/database/result_filter.py"
        for ev in match.evidence
    )


def test_repo_with_database_dependency_only_yields_cwe_89_indirect(tmp_path: Path) -> None:
    repo = tmp_path / "dep-only"
    _init_repo(
        repo,
        {
            "requirements.txt": "sqlalchemy\n",
            "app/main.py": "import sqlalchemy\nengine = sqlalchemy.create_engine('sqlite://')\n",
        },
    )
    result = profile_repository(repo)
    match = next((item for item in result.suggestions if item.cwe_id == "CWE-89"), None)
    assert match is not None
    assert match.relevance_tier == "indirect"
