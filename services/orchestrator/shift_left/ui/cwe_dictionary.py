"""Offline CWE reference dictionary for UI popovers (no runtime network access)."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from shift_left.config import UnclaimedFilesGateConfig, _default_policy_rules, resolve_repo_root
from shift_left.handlers.config.rules.registry import ALL_RULES

_DICTIONARY_REL = Path("data") / "cwe" / "cwe-dictionary.json"
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)


def normalize_cwe_id(value: str) -> str:
    text = value.strip().upper()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text


def cwe_dictionary_path() -> Path:
    return resolve_repo_root() / _DICTIONARY_REL


@lru_cache(maxsize=1)
def load_cwe_dictionary() -> dict[str, dict[str, Any]]:
    """Load bundled CWE dictionary from the repository (local file only)."""
    path = cwe_dictionary_path()
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries: dict[str, dict[str, Any]] = {}
    for key, value in raw.items():
        if not isinstance(value, dict):
            continue
        cwe_id = normalize_cwe_id(str(value.get("id") or key))
        entries[cwe_id] = {
            "id": cwe_id,
            "name": str(value.get("name") or ""),
            "abstraction": str(value.get("abstraction") or ""),
            "short_description": str(value.get("short_description") or ""),
            "url": str(value.get("url") or ""),
        }
    return entries


def _json_script_safe(text: str) -> str:
    """Escape JSON text embedded in HTML <script> blocks (breakout-safe for <, >, &)."""
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def cwe_dictionary_json() -> str:
    """Serialize dictionary for embedding in HTML (client-side popover lookup)."""
    raw = json.dumps(load_cwe_dictionary(), separators=(",", ":"))
    return _json_script_safe(raw)


def known_model_asserted_cwe_ids() -> frozenset[str]:
    """CWE ids that may appear as model_asserted_cwe (scripted engine + observed inference)."""
    return frozenset(
        {
            "CWE-284",  # ScriptedEvalEngine; real inference (terraform permissive)
            "CWE-20",  # Real Foundation-Sec inference (terraform scoped false positive)
        }
    )


def required_dictionary_cwe_ids() -> frozenset[str]:
    """All CWE ids that must exist in the bundled dictionary."""
    return required_registry_and_gate_cwe_ids() | known_model_asserted_cwe_ids()


def model_cwe_recognition(value: str | None) -> tuple[str | None, bool | None]:
    """Return verbatim model CWE (whitespace-trimmed) and dictionary membership flag."""
    if value is None or not str(value).strip():
        return None, None
    raw = str(value).strip()
    normalized = normalize_cwe_id(raw)
    if not _CWE_RE.match(normalized):
        return raw, False
    return raw, normalized in load_cwe_dictionary()


def apply_model_asserted_cwe_fields(
    *,
    model_asserted_cwe: str | None,
    legacy_cwe: str | None = None,
) -> tuple[str | None, bool | None]:
    """Resolve model_asserted_cwe verbatim and model_cwe_recognized from API payload."""
    raw = model_asserted_cwe if model_asserted_cwe is not None else legacy_cwe
    return model_cwe_recognition(raw)


def unrecognized_model_cwe_tally(findings: list[Any]) -> dict[str, Any]:
    """Count model-asserted CWE ids absent from the local dictionary (advisory evidence)."""
    total = 0
    by_cwe_id: dict[str, int] = {}
    for finding in findings:
        model_cwe = getattr(finding, "model_asserted_cwe", None)
        recognized = getattr(finding, "model_cwe_recognized", None)
        if model_cwe and recognized is False:
            total += 1
            by_cwe_id[model_cwe] = by_cwe_id.get(model_cwe, 0) + 1
    return {"total": total, "by_cwe_id": dict(sorted(by_cwe_id.items()))}


def sanitize_model_asserted_cwe(value: str | None) -> str | None:
    """Deprecated: use model_cwe_recognition — retains value, use model_cwe_recognized flag."""
    raw, _recognized = model_cwe_recognition(value)
    return raw


def required_registry_and_gate_cwe_ids() -> frozenset[str]:
    """CWE ids referenced by registry rules (enabled or disabled) and default gate policies."""
    ids: set[str] = set()
    for rule in ALL_RULES:
        ids.add(normalize_cwe_id(rule.cwe))
    gate = UnclaimedFilesGateConfig()
    ids.add(normalize_cwe_id(gate.handler_asserted_cwe))
    for policy in _default_policy_rules():
        for policy_rule in policy.rules:
            for cwe in policy_rule.cwe_blocklist:
                ids.add(normalize_cwe_id(cwe))
    return frozenset(ids)


def orphan_dictionary_entries() -> frozenset[str]:
    required = required_dictionary_cwe_ids()
    return frozenset(load_cwe_dictionary()) - required


def missing_dictionary_entries() -> frozenset[str]:
    required = required_dictionary_cwe_ids()
    return required - frozenset(load_cwe_dictionary())
