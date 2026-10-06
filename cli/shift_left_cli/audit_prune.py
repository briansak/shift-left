"""Operator-initiated audit log pruning with export-first guarantee."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from shift_left.config import load_config, resolve_audit_sqlite_path
from shift_left.models.database import AuditStore


def audit_prune(root: Path, *, before: str, export_path: Path) -> None:
    config_path = root / "config" / "shift-left.yaml"
    if not config_path.exists():
        config_path = root / "config" / "shift-left.example.yaml"
    config = load_config(config_path)
    store = AuditStore(resolve_audit_sqlite_path(config), retention_days=config.audit.retention_days)

    before_dt = datetime.fromisoformat(before)
    if before_dt.tzinfo is None:
        before_dt = before_dt.replace(tzinfo=datetime.now().astimezone().tzinfo)

    try:
        result = store.prune_before(
            before=before_dt,
            export_path=export_path,
            actor="operator:cli",
        )
    except OSError as exc:
        raise SystemExit(f"Export failed — prune aborted: {exc}") from exc

    print(json.dumps(result, indent=2))
