"""Stream sandbox command audit events to the orchestrator as they occur."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from antares_server.sandbox_audit import SandboxCommandAudit

logger = logging.getLogger(__name__)


class HttpAuditSink:
    """POST each command audit event to the orchestrator redaction chokepoint."""

    def __init__(
        self,
        callback_url: str,
        *,
        actor: str,
        subject: str,
        audit_token: str | None = None,
        timeout_seconds: float = 3.0,
    ) -> None:
        self._callback_url = callback_url.rstrip("/")
        self._actor = actor
        self._subject = subject
        self._audit_token = audit_token
        self._timeout_seconds = timeout_seconds

    def record(self, event: SandboxCommandAudit) -> None:
        payload = {
            "actor": self._actor,
            "subject": self._subject,
            **event.to_dict(),
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._audit_token:
            headers["Authorization"] = f"Bearer {self._audit_token}"
        request = urllib.request.Request(
            self._callback_url,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:
                if response.status >= 400:
                    raise RuntimeError(f"audit callback HTTP {response.status}")
        except Exception as exc:  # noqa: BLE001 — audit must not abort investigation
            logger.warning(
                "sandbox audit callback failed investigation=%s command=%r: %s",
                event.investigation_id,
                event.command,
                exc,
            )
