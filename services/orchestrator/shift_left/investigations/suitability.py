"""CWE suitability hints from the Antares model card."""

from __future__ import annotations

STRONG_CWES: frozenset[str] = frozenset({"CWE-843", "CWE-1321"})
WEAK_CWES: frozenset[str] = frozenset({"CWE-732", "CWE-667", "CWE-401"})

SNAPSHOT_WARN_BYTES = 10 * 1024 * 1024


def normalize_task_cwe(value: str) -> str:
    text = value.strip().upper()
    if not text:
        raise ValueError("task_cwe is required")
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    digits = text[4:]
    if not digits.isdigit():
        raise ValueError(f"task_cwe is malformed: {value!r}")
    return text


def cwe_suitability_hint(task_cwe: str) -> str | None:
    normalized = normalize_task_cwe(task_cwe)
    if normalized in STRONG_CWES:
        return f"{normalized} is a strong match on the published Antares model card."
    if normalized in WEAK_CWES:
        return (
            f"{normalized} is a weak match on the published Antares model card — "
            "results may be sparse."
        )
    return None
