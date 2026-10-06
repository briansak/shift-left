"""Launch preflight — antares availability and model variant gates."""

from __future__ import annotations

from dataclasses import dataclass

from shift_left.antares.client import AntaresClient
from shift_left.config import AppConfig


@dataclass(frozen=True)
class LaunchPreflight:
    can_submit: bool
    disabled_reason: str | None = None
    system_href: str = "/ui/system"


def variant_below_minimum(config: AppConfig) -> bool:
    variant = config.antares_triage.model_variant.lower()
    minimum = config.antares_triage.minimum_variant
    if minimum == "1b" and "350m" in variant:
        return True
    return False


def minimum_variant_message(config: AppConfig) -> str:
    return (
        f"Staged model variant {config.antares_triage.model_variant!r} is below the "
        f"minimum ({config.antares_triage.minimum_variant}). Stage Antares-1B on System."
    )


async def check_antares_server_available(client: AntaresClient) -> bool:
    try:
        payload = await client.health()
        return str(payload.get("status", "")).lower() == "ok"
    except Exception:
        return False


async def build_launch_preflight(config: AppConfig, client: AntaresClient) -> LaunchPreflight:
    if not config.antares_triage.enabled:
        return LaunchPreflight(
            can_submit=False,
            disabled_reason="Antares triage is disabled in configuration.",
        )
    if variant_below_minimum(config):
        return LaunchPreflight(
            can_submit=False,
            disabled_reason=minimum_variant_message(config),
        )
    if not await check_antares_server_available(client):
        return LaunchPreflight(
            can_submit=False,
            disabled_reason=(
                "antares-server is unavailable. Install or start it from System before launching."
            ),
        )
    return LaunchPreflight(can_submit=True)
