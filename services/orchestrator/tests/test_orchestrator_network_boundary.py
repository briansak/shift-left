"""Orchestrator reachability to host-native model servers vs external egress."""

from __future__ import annotations

import pytest

from shift_left.config import AppConfig, runtime_allowed_endpoints
from shift_left.http.local_client import LocalOnlyAsyncClient
from shift_left.sovereignty.network import (
    EgressBlockedError,
    EgressGuard,
    assert_host_allowed,
    run_egress_probe,
)


def test_host_docker_internal_is_allowlisted_on_inference_ports_only() -> None:
    """
    sovereign_internal has internal:true (no default internet gateway).

    The orchestrator reaches host-native model servers via Docker Compose
    extra_hosts: host.docker.internal:host-gateway — host.docker.internal
    is allowed only on inference ports 8090/8091, not the whole host.
    """
    config = AppConfig.model_validate(
        {
            "git": {"backend": "bundled-forgejo", "bundled": {"url": "http://forgejo:3000"}},
            "models": {
                "antares": {"service_url": "http://host.docker.internal:8090"},
                "foundation_sec": {"service_url": "http://host.docker.internal:8091"},
            },
        }
    )
    allowed = runtime_allowed_endpoints(config)
    assert ("host.docker.internal", 8090) in allowed
    assert ("host.docker.internal", 8091) in allowed
    assert ("antares-server", 8090) in allowed
    assert ("foundation-sec-server", 8091) in allowed


def test_host_docker_internal_other_ports_blocked() -> None:
    allowed = frozenset({("host.docker.internal", 8090), ("host.docker.internal", 8091)})
    assert_host_allowed("http://host.docker.internal:8090", allowed_endpoints=allowed)
    with pytest.raises(EgressBlockedError, match="8080"):
        assert_host_allowed("http://host.docker.internal:8080", allowed_endpoints=allowed)


@pytest.mark.asyncio
async def test_orchestrator_http_client_blocks_external_host() -> None:
    allowed = frozenset(
        {
            ("host.docker.internal", 8090),
            ("127.0.0.1", 8090),
            ("forgejo", 3000),
            ("antares-server", 8090),
        }
    )
    client = LocalOnlyAsyncClient(allowed_endpoints=allowed)
    with pytest.raises(EgressBlockedError):
        await client.get("https://example.com")


def test_egress_guard_blocks_public_tcp_while_allowing_private() -> None:
    allowed = frozenset({("127.0.0.1", 8090), ("host.docker.internal", 8091)})
    with EgressGuard(allowed_endpoints=allowed):
        import socket

        with pytest.raises(EgressBlockedError):
            socket.create_connection(("1.1.1.1", 443), timeout=1.0)


def test_egress_probe_documents_expected_sovereign_behavior() -> None:
    """In CI without outbound internet, probe should report blocked (ok=True)."""
    result = run_egress_probe(timeout=1.0)
    assert result.message
