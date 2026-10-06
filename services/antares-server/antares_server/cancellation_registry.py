"""Cooperative cancellation for in-flight agent queries.

The agent loop checks cancellation only at **turn boundaries** (before each model
generation step and before dispatching the next terminal command). Hitting the
cancel API sets the flag immediately and antares-server also force-removes the
Docker sandbox container by investigation id without waiting for the loop to exit.

Worst-case delay before the loop stops is therefore bounded by the in-flight
``docker exec`` host timeout (default 10 seconds) or an in-flight model call —
not by container lifetime after cancel.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_events: dict[str, threading.Event] = {}


def register(investigation_id: str) -> threading.Event:
    event = threading.Event()
    with _lock:
        _events[investigation_id] = event
    return event


def unregister(investigation_id: str) -> None:
    with _lock:
        _events.pop(investigation_id, None)


def request_cancel(investigation_id: str) -> bool:
    with _lock:
        event = _events.get(investigation_id)
    if event is None:
        return False
    event.set()
    return True


def is_cancelled(investigation_id: str) -> bool:
    with _lock:
        event = _events.get(investigation_id)
    return event is not None and event.is_set()
