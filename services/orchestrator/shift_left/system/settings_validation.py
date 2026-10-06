"""Tier 3 setting validation — paths, weights, and allowlisted URLs."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from shift_left.config import AppConfig, resolve_repo_relative_path, resolve_repo_root, runtime_allowed_endpoints
from shift_left.sovereignty.network import EgressBlockedError, assert_host_allowed
from shift_left_shared.weights import (
    VERIFIED_FOUNDATION_SEC_Q4_K_M,
    VERIFIED_FOUNDATION_SEC_Q8_0,
    WeightVerificationError,
    load_prewarm_manifest,
    verify_antares_weights,
    verify_gguf_weight,
)


def _readable_path(path_str: str, *, label: str) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        path = resolve_repo_root() / path
    resolved = path.resolve()
    if not resolved.exists():
        raise ValueError(f"{label}: path does not exist: {resolved}")
    if not os.access(resolved, os.R_OK):
        raise ValueError(f"{label}: path is not readable: {resolved}")
    return resolved


def validate_service_url(url: str, *, config: AppConfig, label: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"{label}: URL must use http or https scheme.")
    if not parsed.hostname:
        raise ValueError(f"{label}: URL must include a host.")
    try:
        assert_host_allowed(url, allowed_endpoints=runtime_allowed_endpoints(config))
    except EgressBlockedError as exc:
        raise ValueError(
            f"{label}: {exc}. Add host:port to sovereignty.runtime_allowed_endpoints "
            "in config/shift-left.yaml and restart, or choose an allowlisted endpoint."
        ) from exc
    return url.rstrip("/")


def validate_weights_path(path_str: str, *, profile: str, config: AppConfig) -> str:
    path = _readable_path(path_str, label=f"{profile} weights path")
    repo_root = resolve_repo_root()
    manifest = load_prewarm_manifest(repo_root)

    if profile == "foundation_sec_q8":
        meta = VERIFIED_FOUNDATION_SEC_Q8_0
    elif profile == "foundation_sec_q4":
        meta = VERIFIED_FOUNDATION_SEC_Q4_K_M
    elif profile == "antares":
        try:
            verify_antares_weights(path, manifest)
        except WeightVerificationError as exc:
            raise ValueError(str(exc)) from exc
        return str(path)
    else:
        raise ValueError(f"Unknown weights profile: {profile}")

    try:
        verify_gguf_weight(
            path,
            manifest,
            manifest_key=meta["manifest_key"],
            verified_meta=meta,
        )
    except WeightVerificationError as exc:
        raise ValueError(str(exc)) from exc
    return str(path)


def validate_use_low_memory(enabled: bool, *, config: AppConfig) -> bool:
    if not enabled:
        return False
    q4_path = resolve_repo_relative_path(config.models.foundation_sec.local_path_low_memory)
    try:
        validate_weights_path(str(q4_path), profile="foundation_sec_q4", config=config)
    except ValueError as exc:
        raise ValueError(
            f"Cannot enable Q4_K_M profile: {exc}. Stage weights first — see Model configuration."
        ) from exc
    return True
