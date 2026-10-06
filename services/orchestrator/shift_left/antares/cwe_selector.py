"""Map changed code paths and hunks to CWE-scoped Antares agent queries."""

from __future__ import annotations

from dataclasses import dataclass

from shift_left.diff.extractor import ChangedFile
from shift_left.handlers.code_cwe_rules import match_code_handler_cwe


@dataclass(frozen=True)
class CweQuery:
    task_cwe: str
    task_cwe_description: str


_CWE_DESCRIPTIONS: dict[str, str] = {
    "CWE-89": "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-79": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-502": "Deserialization of Untrusted Data",
}


def _description(task_cwe: str) -> str:
    return _CWE_DESCRIPTIONS.get(task_cwe, "Security weakness matching the supplied CWE category.")


def select_cwe_queries(files: list[ChangedFile], *, max_queries: int = 5) -> list[CweQuery]:
    """Select CWE queries from changed hunks — one query per CWE, capped by max_queries."""
    selected: list[CweQuery] = []
    seen: set[str] = set()

    for changed in files:
        lowered = changed.path.lower()
        for hunk in changed.hunks:
            match = match_code_handler_cwe(content=hunk.content, path=changed.path)
            if match and match.cwe not in seen:
                seen.add(match.cwe)
                selected.append(CweQuery(task_cwe=match.cwe, task_cwe_description=_description(match.cwe)))

        if "db" in lowered or "sql" in lowered:
            if "CWE-89" not in seen:
                seen.add("CWE-89")
                selected.append(CweQuery(task_cwe="CWE-89", task_cwe_description=_description("CWE-89")))
        if any(token in lowered for token in ("auth", "secret", "credential", "config")):
            if "CWE-798" not in seen:
                seen.add("CWE-798")
                selected.append(CweQuery(task_cwe="CWE-798", task_cwe_description=_description("CWE-798")))

        if len(selected) >= max_queries:
            break

    return selected[:max_queries]
