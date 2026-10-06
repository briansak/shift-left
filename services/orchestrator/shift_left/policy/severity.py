"""Deterministic policy_severity derivation — handler CWE only."""

from __future__ import annotations

from shift_left.config import AppConfig, PolicyConfig
from shift_left.models.schema import Finding, PolicySeverity, Severity


def default_cwe_severity_mapping() -> dict[str, str]:
    return {
        "CWE-89": "high",
        "CWE-78": "high",
        "CWE-79": "medium",
        "CWE-284": "high",
        "CWE-798": "high",
        "CWE-22": "medium",
        "CWE-502": "critical",
        "CWE-269": "high",
        "CWE-250": "high",
        "CWE-287": "high",
        "CWE-319": "high",
        "CWE-327": "high",
        "CWE-657": "high",
        "CWE-693": "medium",
        "CWE-754": "high",
        "CWE-778": "medium",
    }


def _normalize_cwe(value: str | None) -> str | None:
    if not value:
        return None
    text = value.upper().strip()
    if not text.startswith("CWE-"):
        text = f"CWE-{text.replace('CWE', '').strip('-')}"
    return text


def _parse_policy_severity(value: str) -> PolicySeverity | None:
    try:
        parsed = PolicySeverity(value.lower())
    except ValueError:
        return None
    if parsed == PolicySeverity.UNCLASSIFIED:
        return None
    return parsed


def derive_policy_severity(finding: Finding, config: AppConfig | PolicyConfig) -> PolicySeverity:
    """
    Derive policy_severity from handler_asserted_cwe only.

    Model-asserted CWE, trace patterns, and path suffix heuristics are excluded.
    """
    if isinstance(config, AppConfig):
        from shift_left.config import effective_cwe_severity_mapping

        cwe_map = effective_cwe_severity_mapping(config)
    else:
        cwe_map = {**default_cwe_severity_mapping(), **config.cwe_severity_mapping}

    cwe = _normalize_cwe(finding.handler_asserted_cwe)
    if cwe and cwe in cwe_map:
        mapped = _parse_policy_severity(cwe_map[cwe])
        if mapped:
            return mapped

    return PolicySeverity.UNCLASSIFIED


def apply_policy_severities(
    findings: list[Finding],
    config: AppConfig | PolicyConfig,
) -> list[Finding]:
    updated: list[Finding] = []
    for finding in findings:
        policy_severity = derive_policy_severity(finding, config)
        updated.append(finding.model_copy(update={"policy_severity": policy_severity}))
    return updated


def coerce_model_asserted_severity(raw: Severity | str | None) -> Severity:
    if isinstance(raw, Severity):
        return raw
    if raw is None:
        return Severity.MEDIUM
    try:
        return Severity(str(raw).lower())
    except ValueError:
        return Severity.MEDIUM
