"""Relative time formatting for UI display."""

from __future__ import annotations

from datetime import datetime, timezone


def relative_time(value: datetime | None) -> str:
    if value is None:
        return "unknown"
    now = datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = now - value
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    days = hours // 24
    if days < 14:
        return f"{days} day{'s' if days != 1 else ''} ago"
    return value.strftime("%Y-%m-%d")
