"""Prohibited wording guards for UI rendering."""

from __future__ import annotations

import re

PROHIBITED_TRIAGE_WORDS = re.compile(
    r"\b(vulnerabilit(y|ies)\s+found|detected|confirmed|identified\s+vulnerability|exploit)\b",
    re.IGNORECASE,
)

PROHIBITED_VERDICT_WORDS = re.compile(
    r"\b(compliant|approved|safe|cleared|passed\s+review)\b",
    re.IGNORECASE,
)


def sanitize_triage_text(text: str) -> str:
    return PROHIBITED_TRIAGE_WORDS.sub("[redacted]", text or "")


def sanitize_advisory_prose(text: str) -> str:
    return PROHIBITED_VERDICT_WORDS.sub("[redacted]", text or "")


def triage_wording_violations(text: str) -> list[str]:
    return [match.group(0) for match in PROHIBITED_TRIAGE_WORDS.finditer(text or "")]


def verdict_wording_violations(text: str) -> list[str]:
    return [match.group(0) for match in PROHIBITED_VERDICT_WORDS.finditer(text or "")]
