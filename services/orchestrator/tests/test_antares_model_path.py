"""Host-native Antares model path resolution."""

from __future__ import annotations

from pathlib import Path

from shift_left.system.supervisor import _resolve_antares_weights_dir


def test_resolve_antares_weights_dir_falls_back_to_350m_when_1b_missing(tmp_path: Path) -> None:
    weights = tmp_path / "models" / "350m"
    weights.mkdir(parents=True)
    (weights / "config.json").write_text("{}\n")
    resolved = _resolve_antares_weights_dir(tmp_path, {"local_path": "models/1b"})
    assert resolved == weights.resolve()


def test_resolve_antares_weights_dir_uses_config_when_present(tmp_path: Path) -> None:
    weights = tmp_path / "models" / "1b"
    weights.mkdir(parents=True)
    (weights / "config.json").write_text("{}\n")
    resolved = _resolve_antares_weights_dir(tmp_path, {"local_path": "models/1b"})
    assert resolved == weights.resolve()
