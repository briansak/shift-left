"""UI sovereignty checks — loopback bind and external asset scan."""

from __future__ import annotations

import os
import re
from pathlib import Path

from shift_left.config import AppConfig

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_EXTERNAL_REF = re.compile(
    r"(?:https?://(?!(?:127\.0\.0\.1|localhost|\[::1\]))[^\s\"'>)]+)|"
    r"(?://(?!/)[^\s\"'>)]+)|"
    r"(?:fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.|unpkg\.com|jsdelivr\.net)",
    re.IGNORECASE,
)
_UI_ROOT = Path(__file__).resolve().parent
_STATIC_ROOT = _UI_ROOT / "static"
_TEMPLATES_ROOT = _UI_ROOT / "templates"


def assert_ui_bind_allowed(config: AppConfig) -> None:
    if not config.ui.enabled:
        return
    host = config.orchestrator.host.strip()
    if host in _LOOPBACK_HOSTS:
        return
    if os.environ.get("ALLOW_NON_LOOPBACK_UI", "").lower() in {"1", "true", "yes"}:
        return
    raise RuntimeError(
        f"UI enabled but orchestrator.host={host!r} is not loopback. "
        "Bind to 127.0.0.1 or set ALLOW_NON_LOOPBACK_UI=true explicitly."
    )


def is_loopback_client(host: str | None) -> bool:
    if not host:
        return False
    normalized = host.strip().lower()
    if normalized in _LOOPBACK_HOSTS:
        return True
    if normalized.startswith("127."):
        return True
    return normalized == "::1"


def assert_loopback_client(config: AppConfig, client_host: str | None) -> None:
    if not config.ui.enabled or not config.ui.require_loopback_client:
        return
    if config.ui.allow_remote_view:
        return
    if not is_loopback_client(client_host):
        raise PermissionError(
            "UI is restricted to loopback clients. "
            "Set ui.allow_remote_view=true only with explicit operator acceptance."
        )


def scan_external_asset_references(*, roots: list[Path] | None = None) -> list[str]:
    """Return human-readable violations for build-time / CI checks."""
    scan_roots = roots or [_STATIC_ROOT, _TEMPLATES_ROOT]
    violations: list[str] = []
    for root in scan_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.suffix not in {".html", ".css", ".js", ".jinja", ".jinja2"}:
                continue
            text = path.read_text(encoding="utf-8")
            for match in _EXTERNAL_REF.finditer(text):
                violations.append(f"{path.relative_to(_UI_ROOT)}: external reference {match.group(0)!r}")
    return violations
