"""Runtime network policy — re-exports shared implementation."""

from shift_left_shared.network import (  # noqa: F401
    DEFAULT_ALLOWED_ENDPOINTS,
    DEFAULT_ALLOWED_HOSTS,
    AllowedEndpoint,
    EgressBlockedError,
    EgressGuard,
    EgressProbeResult,
    assert_egress_blocked_at_startup,
    assert_host_allowed,
    endpoint_from_url,
    run_egress_probe,
)
