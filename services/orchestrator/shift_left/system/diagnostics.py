"""Actionable diagnostics for model and network failures."""

from __future__ import annotations

import socket
from urllib.parse import urlparse


def diagnose_service_url_error(service_name: str, service_url: str, cause: Exception) -> dict:
    """Classify connectivity failures — DNS vs TCP vs HTTP."""
    parsed = urlparse(service_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    message = str(cause)
    lowered = message.lower()

    category = "connection"
    root_cause = f"{service_name} health check failed: {message}"
    remediation: list[str] = []

    if any(
        token in lowered
        for token in (
            "nodename nor servname",
            "name or service not known",
            "getaddrinfo",
            "gaierror",
            "temporary failure in name resolution",
            "errno 8",
        )
    ):
        category = "dns_resolution"
        root_cause = (
            f"Hostname {host!r} cannot be resolved from the orchestrator's network context "
            f"(configured URL: {service_url}). This is DNS/hostname resolution — not model inference."
        )
        if host == "foundation-sec-server":
            remediation = [
                "If orchestrator runs in Docker: start the foundation-sec-server Compose profile "
                "(docker compose --profile linux-cpu up -d foundation-sec-server) or set "
                "FOUNDATION_SEC_SERVICE_URL=http://host.docker.internal:8091 for a host-native server.",
                "If orchestrator runs on the host: set models.foundation_sec.service_url to "
                "http://127.0.0.1:8091 and start foundation-sec-server locally.",
            ]
        elif host == "antares-server":
            remediation = [
                "If orchestrator runs in Docker: start antares-server or set "
                "ANTARES_SERVICE_URL=http://host.docker.internal:8090 for host-native Antares.",
                "On Apple Silicon, Antares typically runs host-native for MPS — not in Compose.",
            ]
        else:
            remediation = [
                f"Verify {host}:{port} is reachable from this process and update the service URL in config.",
            ]
    elif "connection refused" in lowered or "errno 61" in lowered:
        category = "connection_refused"
        root_cause = (
            f"{service_name} hostname {host!r} resolves but nothing is listening on port {port}."
        )
        remediation = [
            f"Start {service_name} and confirm it binds to {host}:{port}.",
        ]
    elif "timed out" in lowered or "timeout" in lowered:
        category = "timeout"
        root_cause = f"{service_name} at {service_url} did not respond before the health timeout."
        remediation = ["Check service logs and firewall rules for the management port."]

    dns_resolves: bool | None = None
    if host and host not in {"localhost", "127.0.0.1", "::1"}:
        try:
            socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            dns_resolves = True
        except OSError:
            dns_resolves = False

    return {
        "category": category,
        "root_cause": root_cause,
        "remediation": remediation,
        "configured_url": service_url,
        "host": host,
        "port": port,
        "dns_resolves": dns_resolves,
        "raw_error": message,
    }
