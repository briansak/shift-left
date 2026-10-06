"""Git backend factory."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from shift_left.config import (
    AppConfig,
    resolve_antares_service_url,
    resolve_foundation_sec_service_url,
)
from shift_left.git.protocol import GitBackendKind
from shift_left.git.forgejo import BundledForgejoBackend
from shift_left.git.github import GitHubBackend
from shift_left.git.gitlab import GitLabBackend
from shift_left.git.protocol import GitBackend
from shift_left_shared.network import DEFAULT_ALLOWED_ENDPOINTS, AllowedEndpoint, endpoint_from_url

logger = logging.getLogger(__name__)


def _parse_extra_endpoint(value: str) -> AllowedEndpoint:
    if ":" not in value:
        raise ValueError(
            f"runtime_allowed_endpoints entry must be host:port, got {value!r}"
        )
    host, port_text = value.rsplit(":", 1)
    return (host.strip(), int(port_text))


def git_http_allowed_endpoints(config: AppConfig) -> frozenset[AllowedEndpoint]:
    """Runtime HTTP allowlist: git API + local inference ports only."""
    endpoints: set[AllowedEndpoint] = set(DEFAULT_ALLOWED_ENDPOINTS)

    git = config.git
    if git.backend == GitBackendKind.BUNDLED_FORGEJO:
        endpoints.add(endpoint_from_url(git.bundled.url))
    elif git.backend == GitBackendKind.GITHUB:
        endpoints.add(endpoint_from_url(git.github.api_url))
    elif git.backend == GitBackendKind.GITLAB:
        endpoints.add(endpoint_from_url(git.gitlab.api_url))

    if (
        config.models.antares.enabled
        or config.antares_triage.enabled
        or config.models.antares.installed
        or config.antares_triage.installed
    ):
        endpoints.add(endpoint_from_url(resolve_antares_service_url(config)))
    if config.models.foundation_sec.enabled:
        endpoints.add(endpoint_from_url(resolve_foundation_sec_service_url(config)))

    for extra in config.sovereignty.runtime_allowed_endpoints:
        endpoints.add(_parse_extra_endpoint(extra))

    return frozenset(endpoints)


def git_http_allowed_hosts(config: AppConfig) -> frozenset[str]:
    """Deprecated — use git_http_allowed_endpoints for port-scoped checks."""
    return frozenset(host for host, _port in git_http_allowed_endpoints(config))


def create_git_backend(config: AppConfig) -> GitBackend:
    allowed = git_http_allowed_endpoints(config)
    git = config.git

    if git.backend == GitBackendKind.BUNDLED_FORGEJO:
        return BundledForgejoBackend(
            git.bundled.url,
            git.token(),
            provider=git.bundled.provider,
            allowed_endpoints=allowed,
        )

    if not git.external_sovereignty_acknowledged:
        raise RuntimeError(
            f"Git backend '{git.backend.value}' requires customer code to transit an "
            "external provider. Set git.external_sovereignty_acknowledged: true after "
            "reading docs/git-backends.md."
        )

    logger.warning(
        "Using non-sovereign git backend '%s' — customer diffs and PR comments egress "
        "to external provider. See docs/git-backends.md for tradeoffs.",
        git.backend.value,
    )

    if git.backend == GitBackendKind.GITHUB:
        return GitHubBackend(
            git.github.api_url,
            git.token(),
            allowed_endpoints=allowed,
        )

    if git.backend == GitBackendKind.GITLAB:
        return GitLabBackend(
            git.gitlab.api_url,
            git.token(),
            allowed_endpoints=allowed,
        )

    raise ValueError(f"Unsupported git backend: {git.backend}")
