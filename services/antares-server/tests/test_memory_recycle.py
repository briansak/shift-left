"""Antares resident-for-run memory lifecycle."""

from __future__ import annotations

import os

from antares_server.inference import AntaresEngine


def test_unload_after_run_increments_counter_and_recycles(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ANTARES_RECYCLE_AFTER_RUNS", "2")
    engine = AntaresEngine(str(tmp_path), load_strategy="resident_for_run")
    engine._model = object()
    engine._tokenizer = object()

    first = engine.unload_after_run()
    assert first["runs_since_recycle"] == 1
    assert first["recycled"] is False

    second = engine.unload_after_run()
    assert second["runs_since_recycle"] == 0
    assert second["recycled"] is True


def test_recycle_threshold_from_environment(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ANTARES_RECYCLE_AFTER_RUNS", "5")
    engine = AntaresEngine(str(tmp_path))
    assert engine._recycle_after_runs == 5
    monkeypatch.delenv("ANTARES_RECYCLE_AFTER_RUNS", raising=False)
    default_engine = AntaresEngine(str(tmp_path))
    assert default_engine._recycle_after_runs == 10
