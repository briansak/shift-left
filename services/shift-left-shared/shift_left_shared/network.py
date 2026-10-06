"""Runtime network policy — egress probe and HTTP endpoint allowlist."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

# (hostname, port) — host.docker.internal is restricted to inference ports only.
AllowedEndpoint = tuple[str, int]

DEFAULT_ALLOWED_ENDPOINTS: frozenset[AllowedEndpoint] = frozenset(
    {
        ("127.0.0.1", 8090),
        ("127.0.0.1", 8091),
        ("localhost", 8090),
        ("localhost", 8091),
        ("::1", 8090),
        ("::1", 8091),
        ("host.docker.internal", 8090),
        ("host.docker.internal", 8091),
        ("antares-server", 8090),
        ("foundation-sec-server", 8091),
        ("forgejo", 3000),
    }
)

# Backward-compatible alias for code that only checked hostnames (deprecated).
DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset(host for host, _port in DEFAULT_ALLOWED_ENDPOINTS)

DEFAULT_EGRESS_PROBE_HOST = "1.1.1.1"
DEFAULT_EGRESS_PROBE_PORT = 443


class EgressBlockedError(RuntimeError):
    """Raised when runtime code attempts outbound access outside the local allowlist."""


@dataclass(frozen=True)
class EgressProbeResult:
    ok: bool
    message: str


def default_port(scheme: str, port: int | None) -> int:
    if port is not None:
        return port
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return 80


def endpoint_from_url(url: str) -> AllowedEndpoint:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError(f"Invalid URL (no host): {url}")
    return (host, default_port(parsed.scheme, parsed.port))


def run_egress_probe(
    *,
    host: str = DEFAULT_EGRESS_PROBE_HOST,
    port: int = DEFAULT_EGRESS_PROBE_PORT,
    timeout: float = 2.0,
) -> EgressProbeResult:
    """
    Attempt outbound TCP to a public address.

    ok=True when connection fails (expected in sovereign runtime).
    ok=False when connection succeeds (runtime egress leak).
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return EgressProbeResult(
            ok=False,
            message=(
                f"Egress probe succeeded to {host}:{port}. "
                "Runtime must not reach the public internet during review."
            ),
        )
    except OSError:
        return EgressProbeResult(
            ok=True,
            message=f"Egress probe blocked to {host}:{port} (expected).",
        )


def assert_egress_blocked_at_startup(
    env: dict[str, str],
    *,
    service_name: str,
    probe_host: str = DEFAULT_EGRESS_PROBE_HOST,
    probe_port: int = DEFAULT_EGRESS_PROBE_PORT,
) -> None:
    """Fail loud if external egress is available unless explicitly skipped."""
    if env.get("SHIFT_LEFT_SKIP_EGRESS_PROBE", "").lower() in {"1", "true", "yes"}:
        return
    if env.get("SHIFT_LEFT_EGRESS_PROBE", "true").lower() in {"0", "false", "no"}:
        return
    result = run_egress_probe(host=probe_host, port=probe_port)
    if not result.ok:
        raise RuntimeError(f"{service_name} sovereignty check failed: {result.message}")


def assert_host_allowed(
    url: str,
    *,
    allowed_endpoints: frozenset[AllowedEndpoint] | None = None,
    allowed_hosts: frozenset[str] | None = None,
) -> None:
    """
    Enforce runtime HTTP allowlist by (host, port).

    ``allowed_hosts`` is deprecated — port-scoped ``allowed_endpoints`` is required
    for host-native inference (8090/8091 only on host.docker.internal).
    """
    endpoint = endpoint_from_url(url)
    host, port = endpoint

    if allowed_endpoints is not None:
        if endpoint in allowed_endpoints:
            return
        raise EgressBlockedError(
            f"Runtime egress blocked for endpoint '{host}:{port}'. "
            "Analyzed artifacts must not leave this host."
        )

    if allowed_hosts is not None:
        if host in allowed_hosts:
            return
        raise EgressBlockedError(
            f"Runtime egress blocked for host '{host}'. "
            "Analyzed artifacts must not leave this host."
        )

    if endpoint in DEFAULT_ALLOWED_ENDPOINTS:
        return

    raise EgressBlockedError(
        f"Runtime egress blocked for endpoint '{host}:{port}'. "
        "Analyzed artifacts must not leave this host."
    )


class EgressGuard:
    """Socket-level guard for sovereignty tests."""

    def __init__(
        self,
        *,
        allowed_endpoints: frozenset[AllowedEndpoint] | None = None,
        allowed_hosts: frozenset[str] | None = None,
    ) -> None:
        self._allowed_endpoints = allowed_endpoints
        self._allowed_hosts = allowed_hosts
        self._original_connect = socket.socket.connect
        self._active = False

    def __enter__(self) -> EgressGuard:
        allowed_endpoints = self._allowed_endpoints
        allowed_hosts = self._allowed_hosts
        original = self._original_connect
        guard = self

        def guarded_connect(sock: socket.socket, address: object) -> None:
            if guard._active and isinstance(address, tuple) and len(address) >= 2:
                host = str(address[0])
                port = int(address[1])
                if allowed_endpoints is not None:
                    if (host, port) not in allowed_endpoints:
                        raise EgressBlockedError(
                            f"Socket connect to '{host}:{port}' blocked by runtime egress guard"
                        )
                elif allowed_hosts is not None:
                    if host not in allowed_hosts:
                        raise EgressBlockedError(
                            f"Socket connect to '{host}' blocked by runtime egress guard"
                        )
            return original(sock, address)

        socket.socket.connect = guarded_connect  # type: ignore[method-assign]
        self._active = True
        return self

    def __exit__(self, *args: object) -> None:
        self._active = False
        socket.socket.connect = self._original_connect  # type: ignore[method-assign]
