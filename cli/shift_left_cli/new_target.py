"""Scaffold a managed target entry in operator config."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


def _config_path(root: Path) -> Path:
    return root / "config" / "shift-left.yaml"


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.strip().lower())
    slug = slug.strip("-")
    return slug or "target"


def scaffold_new_target(
    root: Path,
    *,
    display_name: str,
    target_type: str,
    repo: str,
    branch: str = "main",
    config_paths: list[str] | None = None,
    environment: str = "",
    criticality: str = "",
    owner: str = "",
    deployment_adapter: str = "unconfigured",
) -> dict[str, str]:
    config_path = _config_path(root)
    if not config_path.is_file():
        raise FileNotFoundError(f"Config not found: {config_path}")

    raw = yaml.safe_load(config_path.read_text()) or {}
    managed = raw.setdefault("managed_targets", {})
    targets = managed.setdefault("targets", [])
    target_id = _slugify(display_name)
    existing = {item.get("id") for item in targets if isinstance(item, dict)}
    suffix = 2
    base_id = target_id
    while target_id in existing:
        target_id = f"{base_id}-{suffix}"
        suffix += 1

    entry = {
        "id": target_id,
        "display_name": display_name,
        "target_type": target_type,
        "description": "",
        "repo": repo,
        "branch": branch,
        "config_paths": config_paths or ["terraform/**"],
        "deployment_adapter": deployment_adapter,
        "deployment_adapter_settings": {},
        "environment": environment,
        "criticality": criticality,
        "owner": owner,
    }
    targets.append(entry)
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    return {"id": target_id, "config_path": str(config_path)}


def operator_new_target(args) -> int:
    root = args.root.resolve()
    paths = [item.strip() for item in (args.config_paths or "").split(",") if item.strip()]
    result = scaffold_new_target(
        root,
        display_name=args.display_name,
        target_type=args.target_type,
        repo=args.repo,
        branch=args.branch,
        config_paths=paths or None,
        environment=args.environment or "",
        criticality=args.criticality or "",
        owner=args.owner or "",
        deployment_adapter=args.deployment_adapter,
    )
    print(f"Added managed target '{result['id']}' to {result['config_path']}")
    print("Restart the orchestrator to load the new target.")
    return 0
