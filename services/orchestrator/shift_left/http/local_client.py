"""Local-only async HTTP client for runtime pipeline services."""

from __future__ import annotations

from typing import Any

import httpx

from shift_left.config import ModelStageTimeouts
from shift_left.sovereignty.network import AllowedEndpoint, EgressBlockedError, assert_host_allowed


def httpx_timeout_from_stage_budgets(
    budgets: ModelStageTimeouts,
    *,
    default_seconds: float | None = None,
) -> httpx.Timeout:
    """Build httpx.Timeout from per-stage model budgets."""
    generation = budgets.generation
    if default_seconds is not None:
        generation = max(generation, default_seconds)
    return httpx.Timeout(
        connect=budgets.connect,
        read=generation,
        write=budgets.prompt,
        pool=budgets.connect,
    )


class LocalOnlyAsyncClient:
    """
    httpx wrapper that enforces runtime egress policy before every request.

    No telemetry headers are added. No retry to external fallback endpoints.
    """

    def __init__(
        self,
        *,
        timeout: float | httpx.Timeout = 60.0,
        allowed_endpoints: frozenset[AllowedEndpoint] | None = None,
        allowed_hosts: frozenset[str] | None = None,
        stage_timeouts: ModelStageTimeouts | None = None,
    ) -> None:
        if stage_timeouts is not None:
            default = timeout if isinstance(timeout, (int, float)) else None
            self._timeout: float | httpx.Timeout = httpx_timeout_from_stage_budgets(
                stage_timeouts,
                default_seconds=default,
            )
        else:
            self._timeout = timeout
        self._allowed_endpoints = allowed_endpoints
        self._allowed_hosts = allowed_hosts
        self._stage_timeouts = stage_timeouts

    def _check(self, url: str) -> None:
        assert_host_allowed(
            url,
            allowed_endpoints=self._allowed_endpoints,
            allowed_hosts=self._allowed_hosts,
        )

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        self._check(url)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await client.get(url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        self._check(url)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await client.post(url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self._check(url)
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await client.request(method, url, **kwargs)


def raise_local_inference_error(service: str, cause: Exception) -> None:
    """Fail closed — never suggest or use a hosted API fallback."""
    raise RuntimeError(
        f"Local {service} inference failed: {cause}. "
        "Shift-Left does not fall back to hosted APIs. "
        "Verify model weights are staged locally and the inference service is running."
    ) from cause
