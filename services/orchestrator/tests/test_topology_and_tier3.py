"""Topology detection and Compose CLI probing."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from shift_left.config import AppConfig
from shift_left.system.compose_cli import detect_compose_cli, invalidate_compose_cli_cache
from shift_left.system.topology import detect_topology, invalidate_topology_cache


@pytest.fixture(autouse=True)
def clear_caches():
    invalidate_topology_cache()
    invalidate_compose_cli_cache()
    yield
    invalidate_topology_cache()
    invalidate_compose_cli_cache()


def test_topology_host_native_without_compose_dns() -> None:
    with patch("shift_left.system.topology._in_dockerenv", return_value=False):
        with patch("shift_left.system.topology._cgroup_indicates_container", return_value=False):
            with patch("shift_left.system.topology._compose_dns_resolves", return_value=False):
                with patch("shift_left.system.topology._docker_socket_available", return_value=False):
                    report = detect_topology()
    assert report.topology_label == "host-native"
    assert report.compose_dns_resolves is False
    assert report.prior_mismatch == []


def test_topology_compose_container_with_dns() -> None:
    with patch("shift_left.system.topology._in_dockerenv", return_value=True):
        with patch("shift_left.system.topology._cgroup_indicates_container", return_value=True):
            with patch("shift_left.system.topology._compose_dns_resolves", return_value=True):
                with patch("shift_left.system.topology._docker_socket_available", return_value=True):
                    with patch.dict(
                        "os.environ",
                        {
                            "ANTARES_SERVICE_URL": "http://host.docker.internal:8090",
                            "FOUNDATION_SEC_SERVICE_URL": "http://host.docker.internal:8091",
                        },
                        clear=False,
                    ):
                        report = detect_topology()
    assert report.topology_label == "docker-compose"
    assert report.model_hosting == "host-native-macos"
    assert report.service_control_mode == "compose-via-docker-socket"


def test_compose_cli_prefers_docker_compose_plugin() -> None:
    with patch("shift_left.system.compose_cli._probe_form", side_effect=lambda prefix: prefix == ("docker", "compose")):
        report = detect_compose_cli()
    assert report.available
    assert report.form == "docker compose"
    assert report.argv_prefix == ("docker", "compose")


def test_compose_cli_falls_back_to_docker_compose_binary() -> None:
    with patch(
        "shift_left.system.compose_cli._probe_form",
        side_effect=lambda prefix: prefix == ("docker-compose",),
    ):
        report = detect_compose_cli()
    assert report.available
    assert report.form == "docker-compose"


def test_compose_cli_config_override() -> None:
    with patch("shift_left.system.compose_cli._probe_form", return_value=True):
        report = detect_compose_cli(config_override="docker-compose")
    assert report.argv_prefix == ("docker-compose",)


def test_compose_cli_failure_lists_both_forms() -> None:
    with patch("shift_left.system.compose_cli._probe_form", return_value=False):
        report = detect_compose_cli()
    assert not report.available
    assert "docker compose" in report.error
    assert "docker-compose" in report.error


def test_service_url_outside_allowlist_rejected() -> None:
    from shift_left.system.settings_validation import validate_service_url

    config = AppConfig.model_validate({"orchestrator": {"host": "127.0.0.1"}})
    with pytest.raises(ValueError, match="allowlist"):
        validate_service_url("http://evil.example.com:8090", config=config, label="Antares")


def test_q4_profile_blocked_when_unstaged(tmp_path) -> None:
    from shift_left.system.settings_validation import validate_use_low_memory

    config = AppConfig.model_validate(
        {
            "orchestrator": {"host": "127.0.0.1"},
            "models": {
                "foundation_sec": {
                    "enabled": True,
                    "local_path_low_memory": str(tmp_path / "missing-q4"),
                }
            },
        }
    )
    with pytest.raises(ValueError, match="Q4_K_M"):
        validate_use_low_memory(True, config=config)


def test_compose_exec_argv_uses_detected_form() -> None:
    from shift_left.system.services import compose_exec_argv

    config = AppConfig.model_validate({"orchestrator": {"host": "127.0.0.1"}})
    with patch("shift_left.system.compose_cli.compose_argv_prefix", return_value=("docker-compose",)):
        argv = compose_exec_argv(config, "postgres", "psql", "-c", "SELECT 1")
    assert argv[0] == "docker-compose"
    assert "exec" in argv
    assert "postgres" in argv
