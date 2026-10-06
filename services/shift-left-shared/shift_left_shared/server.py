"""Model-server bind and startup hardening."""

from __future__ import annotations

import ipaddress


def resolve_bind_host(env: dict[str, str], *, env_key: str = "MODEL_BIND_HOST") -> str:
    """
    Default loopback-only bind for host-native inference servers.

    Set ALLOW_NON_LOOPBACK_BIND=true to bind 0.0.0.0 (required for in-container
    service discovery on sovereign_internal — document the tradeoff).
    """
    host = env.get(env_key, "127.0.0.1").strip()
    if host == "0.0.0.0":
        if env.get("ALLOW_NON_LOOPBACK_BIND", "").lower() not in {"1", "true", "yes"}:
            raise RuntimeError(
                f"Refusing to bind {env_key}=0.0.0.0 without ALLOW_NON_LOOPBACK_BIND=true. "
                "Host-native deployments must listen on 127.0.0.1 only."
            )
        return host

    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise RuntimeError(f"Invalid {env_key}={host!r}") from exc

    if not addr.is_loopback:
        if env.get("ALLOW_NON_LOOPBACK_BIND", "").lower() not in {"1", "true", "yes"}:
            raise RuntimeError(
                f"Refusing non-loopback bind {env_key}={host} without ALLOW_NON_LOOPBACK_BIND=true."
            )
    return host


def startup_model_server(env: dict[str, str], *, service_name: str, bind_env_key: str) -> str:
    """Shared startup checks for inference servers."""
    from shift_left_shared.runtime import assert_no_remote_inference_fallback
    from shift_left_shared.network import assert_egress_blocked_at_startup

    assert_no_remote_inference_fallback(env)
    assert_egress_blocked_at_startup(env, service_name=service_name)
    return resolve_bind_host(env, env_key=bind_env_key)
