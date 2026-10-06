"""Offline bundle licensing compliance — enforced at bundle time."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shift_left_shared.weights import (
    VERIFIED_ANTARES_350M,
    VERIFIED_FOUNDATION_SEC_Q4_K_M,
    VERIFIED_FOUNDATION_SEC_Q8_0,
    load_prewarm_manifest,
)

APACHE_LICENSE_CANDIDATES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "Apache-2.0.txt")
NOTICE_CANDIDATES = ("NOTICE", "NOTICE.txt", "NOTICE.md")


def _has_file(directory: Path, names: tuple[str, ...]) -> bool:
    return any((directory / name).is_file() for name in names)


def _bundle_license_present(bundle_dir: Path) -> bool:
    licenses_dir = bundle_dir / "licenses"
    if (licenses_dir / "APACHE-2.0.txt").is_file():
        return True
    if (bundle_dir / "LICENSE").is_file():
        return True
    return _has_file(bundle_dir, APACHE_LICENSE_CANDIDATES)


def _model_attribution_ok(model_dir: Path, entry: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not model_dir.is_dir():
        errors.append(f"missing model directory {model_dir}")
        return errors
    if not _has_file(model_dir, APACHE_LICENSE_CANDIDATES):
        errors.append(
            f"{model_dir.name}: missing upstream LICENSE (Apache-2.0 text must be retained)"
        )
    notice_required = entry.get("notice_required", False)
    if notice_required and not _has_file(model_dir, NOTICE_CANDIDATES):
        errors.append(f"{model_dir.name}: missing upstream NOTICE file")
    readme = model_dir / "README.md"
    if not readme.is_file():
        errors.append(f"{model_dir.name}: missing README.md (model card / attribution)")
    return errors


def check_offline_bundle(bundle_dir: Path) -> list[str]:
    """
    Fail bundle production when Apache-2.0 obligations cannot be proven.

    Expected layout:
      bundle_dir/
        licenses/APACHE-2.0.txt
        models/antares-350m/...
        models/foundation-sec/...
        manifest.json
    """
    errors: list[str] = []
    if not bundle_dir.exists():
        return [f"bundle directory not found: {bundle_dir}"]

    if not _bundle_license_present(bundle_dir):
        errors.append(
            "bundle missing licenses/APACHE-2.0.txt (full Apache 2.0 license text required)"
        )

    manifest_path = bundle_dir / "manifest.json"
    manifest = load_prewarm_manifest(bundle_dir.parent) if not manifest_path.exists() else {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())

    models_root = bundle_dir / "models"
    expected = [
        (models_root / "350m", VERIFIED_ANTARES_350M["manifest_key"]),
        (models_root / "foundation-sec-q8_0", VERIFIED_FOUNDATION_SEC_Q8_0["manifest_key"]),
        (models_root / "foundation-sec-q4_k_m", VERIFIED_FOUNDATION_SEC_Q4_K_M["manifest_key"]),
    ]
    for model_dir, key in expected:
        if not model_dir.exists():
            continue
        entry = (manifest.get("models") or {}).get(key) or {}
        errors.extend(_model_attribution_ok(model_dir, entry))

    third_party = bundle_dir / "THIRD_PARTY_NOTICES.md"
    if not third_party.is_file():
        errors.append("bundle missing THIRD_PARTY_NOTICES.md")

    return errors
