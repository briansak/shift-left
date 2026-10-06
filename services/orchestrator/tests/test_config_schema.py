"""Config schema_version guard — stale operator configs fail loudly."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from shift_left.config import AppConfig, CURRENT_SCHEMA_VERSION, load_config, resolve_config_path


@pytest.fixture(autouse=True)
def _clear_storage_path_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHIFT_LEFT_DATA_DIR", raising=False)
    monkeypatch.delenv("SHIFT_LEFT_REPO_ROOT", raising=False)


def _write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "shift-left.yaml"
    path.write_text(yaml.safe_dump(data))
    return path


def test_load_config_requires_schema_version(tmp_path: Path) -> None:
    path = _write_config(tmp_path, {"orchestrator": {"port": 8080}})
    with pytest.raises(ValueError, match="missing required schema_version"):
        load_config(path)


def test_load_config_rejects_stale_quant_fields(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "models": {
                "foundation_sec": {
                    "quant": "Q8_0",
                    "gguf_glob": "*-q8_0.gguf",
                }
            },
        },
    )
    with pytest.raises(ValueError, match="stale configuration keys"):
        load_config(path)


def test_load_config_rejects_runtime_allowed_hosts(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "sovereignty": {"runtime_allowed_hosts": ["extra-host"]},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        },
    )
    with pytest.raises(ValueError, match="runtime_allowed_hosts"):
        load_config(path)


def test_resolve_config_path_finds_repo_config_from_any_cwd(tmp_path: Path, monkeypatch) -> None:
    repo = tmp_path / "repo"
    config_dir = repo / "config"
    config_dir.mkdir(parents=True)
    config_file = config_dir / "shift-left.yaml"
    config_file.write_text("schema_version: 7\n")

    fake_package = repo / "services" / "orchestrator" / "shift_left" / "config.py"
    fake_package.parent.mkdir(parents=True)
    fake_package.write_text("# stub\n")

    monkeypatch.setattr(
        "shift_left.config.__file__",
        str(fake_package),
    )
    monkeypatch.chdir(repo / "services" / "orchestrator")

    resolved = resolve_config_path()
    assert resolved == config_file.resolve()


def test_load_config_resolves_repo_relative_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    config_dir = repo / "config"
    config_dir.mkdir(parents=True)
    path = config_dir / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "findings_store": {"sqlite_path": "data/findings/shift-left.db"},
                "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
            }
        )
    )
    config = load_config(path)
    assert config.findings_store.sqlite_path == str((repo / "data/findings/shift-left.db").resolve())


def test_load_config_accepts_current_schema(tmp_path: Path) -> None:
    path = _write_config(
        tmp_path,
        {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "enrichment": {"enabled": False},
            "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
        },
    )
    config = load_config(path)
    assert config.schema_version == CURRENT_SCHEMA_VERSION


def test_load_config_uses_shift_left_repo_root_not_config_bind_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "data" / "findings").mkdir(parents=True)
    mount = tmp_path / "config"
    mount.mkdir()
    path = mount / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "findings_store": {"sqlite_path": "data/findings/shift-left.db"},
                "antares_triage": {"repos_checkout_dir": "data/repos"},
                "models": {
                    "antares": {"local_path": "models/1b"},
                    "foundation_sec": {"gguf_glob": "*-q8_0.gguf"},
                },
            }
        )
    )
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", str(repo))
    monkeypatch.delenv("SHIFT_LEFT_DATA_DIR", raising=False)
    config = load_config(path)
    assert config.findings_store.sqlite_path == str((repo / "data/findings/shift-left.db").resolve())
    assert config.antares_triage.repos_checkout_dir == str((repo / "data/repos").resolve())
    assert config.models.antares.local_path == "models/1b"


def test_load_config_maps_data_prefix_to_shift_left_data_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    data = tmp_path / "data"
    (data / "findings").mkdir(parents=True)
    (data / "repos").mkdir(parents=True)
    config_dir = repo / "config"
    config_dir.mkdir(parents=True)
    path = config_dir / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "findings_store": {"sqlite_path": "data/findings/shift-left.db"},
                "antares_triage": {"repos_checkout_dir": "data/repos"},
                "investigations": {"sqlite_path": "data/findings/investigations.db"},
                "reference_data": {"cache_dir": "data/reference"},
                "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
            }
        )
    )
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", str(repo))
    monkeypatch.setenv("SHIFT_LEFT_DATA_DIR", str(data))
    config = load_config(path)
    assert config.findings_store.sqlite_path == str(data / "findings/shift-left.db")
    assert config.antares_triage.repos_checkout_dir == str(data / "repos")
    assert config.investigations.sqlite_path == str(data / "findings/investigations.db")
    assert config.reference_data.cache_dir == str(data / "reference")


def test_load_config_rewrites_legacy_container_checkout_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    repo = tmp_path / "repo"
    data = tmp_path / "data"
    data.mkdir()
    config_dir = repo / "config"
    config_dir.mkdir(parents=True)
    path = config_dir / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "antares_triage": {"repos_checkout_dir": "/shift-left/data/repos"},
                "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
            }
        )
    )
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", "/shift-left")
    monkeypatch.setenv("SHIFT_LEFT_DATA_DIR", str(data))
    with caplog.at_level(logging.WARNING, logger="shift_left.config"):
        config = load_config(path)
    assert config.antares_triage.repos_checkout_dir == str(data / "repos")
    assert len(config.legacy_path_rewrites) == 1
    rewrite = config.legacy_path_rewrites[0]
    assert rewrite.key == "antares_triage.repos_checkout_dir"
    assert rewrite.original == "/shift-left/data/repos"
    assert rewrite.resolved == str(data / "repos")
    assert "/shift-left/data/repos" in caplog.text
    assert str(data / "repos") in caplog.text
    assert "antares_triage.repos_checkout_dir" in caplog.text


def test_load_config_rewrites_legacy_slash_data_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    repo = tmp_path / "repo"
    data = tmp_path / "volume"
    data.mkdir()
    config_dir = repo / "config"
    config_dir.mkdir(parents=True)
    path = config_dir / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "reference_data": {"cache_dir": "/data/reference"},
                "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
            }
        )
    )
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", "/shift-left")
    monkeypatch.setenv("SHIFT_LEFT_DATA_DIR", str(data))
    with caplog.at_level(logging.WARNING, logger="shift_left.config"):
        config = load_config(path)
    assert config.reference_data.cache_dir == str(data / "reference")
    assert config.legacy_path_rewrites[0].original == "/data/reference"
    assert "reference_data.cache_dir" in caplog.text


def test_load_config_relative_data_paths_are_not_legacy_rewrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    repo = tmp_path / "repo"
    data = tmp_path / "data"
    data.mkdir()
    config_dir = repo / "config"
    config_dir.mkdir(parents=True)
    path = config_dir / "shift-left.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "schema_version": CURRENT_SCHEMA_VERSION,
                "antares_triage": {"repos_checkout_dir": "data/repos"},
                "models": {"foundation_sec": {"gguf_glob": "*-q8_0.gguf"}},
            }
        )
    )
    monkeypatch.setenv("SHIFT_LEFT_REPO_ROOT", str(repo))
    monkeypatch.setenv("SHIFT_LEFT_DATA_DIR", str(data))
    with caplog.at_level(logging.WARNING, logger="shift_left.config"):
        config = load_config(path)
    assert config.antares_triage.repos_checkout_dir == str(data / "repos")
    assert config.legacy_path_rewrites == []
    assert "legacy config path rewritten" not in caplog.text


def test_example_yaml_documents_advisory_suppression_basis() -> None:
    repo = Path(__file__).resolve().parents[3]
    text = (repo / "config" / "shift-left.example.yaml").read_text()
    assert "~12% recall" in text
    assert "50-65%" in text
    assert "Foundry Constitution II" in text
    assert "operator-burying" in text


def test_example_yaml_matches_schema_version() -> None:
    repo = Path(__file__).resolve().parents[3]
    config = load_config(repo / "config" / "shift-left.example.yaml")
    assert config.schema_version == CURRENT_SCHEMA_VERSION
    assert config.models.antares.local_path == "models/1b"
    assert config.models.antares.hf_repo_id == "fdtn-ai/antares-1b"
    assert config.investigations.batch.size_cap == 25
    assert config.investigations.batch.confirm_threshold == 10
    assert config.advisory_suppression.omit_from_pr_comments is True
    assert config.advisory_suppression.omit_from_review_api is True
    assert config.antares_triage.enabled is False
    assert config.antares_triage.repos_checkout_dir.endswith("/data/repos")


def test_appconfig_defaults_match_1b_minimum_and_schema_extras() -> None:
    config = AppConfig()
    assert config.schema_version == CURRENT_SCHEMA_VERSION
    assert config.models.antares.local_path == "models/1b"
    assert config.models.antares.hf_repo_id == "fdtn-ai/antares-1b"
    assert config.models.antares.enabled is False
    assert config.antares_triage.enabled is False
    assert config.antares_triage.minimum_variant == "1b"
    assert config.antares_triage.repos_checkout_dir == "data/repos"
    assert config.investigations.batch.size_cap == 25
    assert config.investigations.batch.confirm_threshold == 10
    assert config.advisory_suppression.omit_from_pr_comments is True
    assert config.advisory_suppression.omit_from_review_api is True
