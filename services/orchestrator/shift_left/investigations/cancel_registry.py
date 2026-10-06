"""In-flight investigation cancellation coordination."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class ActiveInvestigationRun:
    investigation_id: str
    cancel_event: threading.Event = field(default_factory=threading.Event)
    in_flight_command: str | None = None


class InvestigationCancelRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: dict[str, ActiveInvestigationRun] = {}

    def register(self, investigation_id: str) -> ActiveInvestigationRun:
        run = ActiveInvestigationRun(investigation_id=investigation_id)
        with self._lock:
            self._active[investigation_id] = run
        return run

    def get(self, investigation_id: str) -> ActiveInvestigationRun | None:
        with self._lock:
            return self._active.get(investigation_id)

    def unregister(self, investigation_id: str) -> None:
        with self._lock:
            self._active.pop(investigation_id, None)

    def request_cancel(self, investigation_id: str) -> bool:
        with self._lock:
            run = self._active.get(investigation_id)
        if run is None:
            return False
        run.cancel_event.set()
        return True

    def is_cancelled(self, investigation_id: str) -> bool:
        run = self.get(investigation_id)
        return run is not None and run.cancel_event.is_set()
