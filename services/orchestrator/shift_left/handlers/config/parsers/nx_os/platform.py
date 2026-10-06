"""Platform sniffing for NX-OS vs IOS-XE vs ASA CLI fragments."""

from __future__ import annotations

from shift_left.handlers.config.parsers.ios_xe.platform import (
    SniffedPlatform,
    platform_mismatch_line,
    sniff_platform,
)

__all__ = [
    "SniffedPlatform",
    "platform_mismatch_line",
    "sniff_platform",
]
