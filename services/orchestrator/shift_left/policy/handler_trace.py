"""Parse handler trace strings on gate findings."""

from __future__ import annotations


def handler_rule_id_from_trace(trace: str | None) -> str | None:
    if not trace or not trace.startswith("handler:"):
        return None
    rule_id = trace.removeprefix("handler:")
    if rule_id in {"unclaimed-file"}:
        return None
    return rule_id
