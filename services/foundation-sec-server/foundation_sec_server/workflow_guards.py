"""CI workflow path guards and template-reference detection."""

from __future__ import annotations

import re

_CI_WORKFLOW_PATH = re.compile(
    r"(^|/)\.(github|forgejo)/workflows/",
    re.IGNORECASE,
)
_TEMPLATE_REFERENCE = re.compile(
    r"\$\{\{\s*(secrets|vars|env)\.[^}]+\}\}",
    re.IGNORECASE,
)


def is_ci_workflow_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return bool(_CI_WORKFLOW_PATH.search(normalized))


def contains_only_template_references_for_secrets(content: str) -> bool:
    """True when apparent secret-like tokens are Forgejo/GitHub template references."""
    if not _TEMPLATE_REFERENCE.search(content):
        return False
    # Lines that look like hardcoded secrets but are template refs.
    suspicious = re.findall(
        r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*(\S+)",
        content,
    )
    if not suspicious:
        return True
    for _, value in suspicious:
        if not _TEMPLATE_REFERENCE.search(value):
            return False
    return True


def should_skip_ci_workflow(path: str, content: str) -> bool:
    return is_ci_workflow_path(path)
