"""Map Antares triage query responses to LocalizationResult building blocks."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shift_left.models.schema import RankedFileCandidate


@dataclass(frozen=True)
class TriageQueryPayload:
    outcome: str
    exploration_trace: str
    turn_count: int
    ranked_files: list[RankedFileCandidate]
    terminal_budget: int = 0
    loop_control_enabled: bool = True
    adapter_identity: dict[str, str] = field(default_factory=dict)
    generation_params: dict[str, object] = field(default_factory=dict)
    failure_class: str | None = None
    failure_message: str | None = None
    investigation_id: str = ""
    sandbox_audit: tuple[dict[str, object], ...] = ()


def triage_payload_from_response(data: dict[str, Any]) -> TriageQueryPayload:
    localizations = data.get("localizations") or []
    item = localizations[0] if localizations else {}
    ranked: list[RankedFileCandidate] = []
    for index, path in enumerate(item.get("ranked_files") or [], start=1):
        if str(path).strip():
            ranked.append(RankedFileCandidate(path=str(path), rank=index))
    audit_raw = item.get("sandbox_audit") or []
    audit_tuple = tuple(dict(entry) for entry in audit_raw if isinstance(entry, dict))
    return TriageQueryPayload(
        outcome=str(item.get("outcome") or data.get("outcome") or "failed"),
        exploration_trace=str(item.get("exploration_trace") or ""),
        turn_count=int(item.get("terminal_calls_used") or 0),
        terminal_budget=int(
            item.get("terminal_budget") or data.get("terminal_budget") or 0
        ),
        loop_control_enabled=bool(
            item.get(
                "loop_control_enabled",
                data.get("loop_control_enabled", True),
            )
        ),
        adapter_identity=dict(
            item.get("adapter_identity") or data.get("adapter_identity") or {}
        ),
        generation_params=dict(
            item.get("generation_params") or data.get("generation_params") or {}
        ),
        ranked_files=ranked,
        failure_class=item.get("failure_class") or data.get("failure_class"),
        failure_message=item.get("failure_message") or data.get("failure_message"),
        investigation_id=str(item.get("investigation_id") or ""),
        sandbox_audit=audit_tuple,
    )
