"""CWE dictionary integrity and offline lookup constraints."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from shift_left.ui.cwe_dictionary import (
    _json_script_safe,
    cwe_dictionary_json,
    cwe_dictionary_path,
    known_model_asserted_cwe_ids,
    load_cwe_dictionary,
    missing_dictionary_entries,
    model_cwe_recognition,
    orphan_dictionary_entries,
    required_dictionary_cwe_ids,
    required_registry_and_gate_cwe_ids,
    unrecognized_model_cwe_tally,
)
from shift_left.ui import cwe_dictionary as cwe_dictionary_module


def test_required_registry_and_gate_cwe_ids_enumerated_from_code() -> None:
    required = required_registry_and_gate_cwe_ids()
    assert required == frozenset(
        {
            "CWE-284",
            "CWE-287",
            "CWE-319",
            "CWE-327",
            "CWE-657",
            "CWE-693",
            "CWE-754",
            "CWE-778",
        }
    )


def test_known_model_asserted_cwe_ids_enumerated_from_code() -> None:
    model_ids = known_model_asserted_cwe_ids()
    assert model_ids == frozenset({"CWE-284", "CWE-20"})


def test_required_dictionary_includes_registry_gate_and_model_cwes() -> None:
    required = required_dictionary_cwe_ids()
    assert required_registry_and_gate_cwe_ids() <= required
    assert known_model_asserted_cwe_ids() <= required
    assert required == required_registry_and_gate_cwe_ids() | known_model_asserted_cwe_ids()


def test_dictionary_covers_all_required_cwes() -> None:
    missing = missing_dictionary_entries()
    assert not missing, f"Missing CWE dictionary entries: {sorted(missing)}"


def test_dictionary_orphans_reported_as_warning() -> None:
    orphans = orphan_dictionary_entries()
    if orphans:
        import warnings

        warnings.warn(f"Orphan CWE dictionary entries (not referenced): {sorted(orphans)}")


def test_cwe_lookup_reads_local_file_only() -> None:
    source = inspect.getsource(cwe_dictionary_module)
    lowered = source.lower()
    assert "httpx" not in lowered
    assert "urllib.request" not in lowered
    assert "requests." not in lowered
    assert "aiohttp" not in lowered
    assert "urlopen" not in lowered


def test_load_cwe_dictionary_reads_repo_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", str(tmp_path))
    dict_dir = tmp_path / "data" / "cwe"
    dict_dir.mkdir(parents=True)
    (dict_dir / "cwe-dictionary.json").write_text(
        '{"CWE-284":{"id":"CWE-284","name":"Test","abstraction":"Base",'
        '"short_description":"Local only.","url":"https://example.invalid/284"}}',
        encoding="utf-8",
    )
    load_cwe_dictionary.cache_clear()
    entry = load_cwe_dictionary()["CWE-284"]
    assert entry["name"] == "Test"
    assert entry["short_description"] == "Local only."
    load_cwe_dictionary.cache_clear()


def test_cwe_dictionary_path_under_repo_root() -> None:
    path = cwe_dictionary_path()
    assert path.name == "cwe-dictionary.json"
    assert path.parent.name == "cwe"
    assert path.is_file()


def test_cwe_dictionary_json_escapes_html_script_breakout_chars() -> None:
    payload = '{"CWE-1":{"short_description":"break </script><script>alert(1)</script>"}}'
    safe = _json_script_safe(payload)
    assert "</script>" not in safe
    assert "\\u003c/script" in safe
    assert "\\u003e" in safe


def test_model_cwe_recognition_marks_dictionary_membership() -> None:
    raw, recognized = model_cwe_recognition("CWE-284")
    assert raw == "CWE-284"
    assert recognized is True
    raw, recognized = model_cwe_recognition("cwe-20")
    assert raw == "cwe-20"
    assert recognized is True
    raw, recognized = model_cwe_recognition("CWE-99999")
    assert raw == "CWE-99999"
    assert recognized is False
    raw, recognized = model_cwe_recognition(None)
    assert raw is None
    assert recognized is None
