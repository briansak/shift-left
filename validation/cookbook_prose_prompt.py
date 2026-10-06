"""Cookbook-format prose prompt for Experiment F (detection-only, no structured output)."""

from __future__ import annotations

# Verbatim cookbook prompt shape (Foundation-Sec config-review recipe).
COOKBOOK_PROMPT_SHAPE = (
    "You are a security auditor. Assess the following configuration for "
    "misconfigurations, weak settings, and missing best practices. For each issue "
    "you find, respond with the detected misconfiguration, severity, and "
    "recommended fix."
)

COOKBOOK_PROMPT_TEMPLATE = (
    COOKBOOK_PROMPT_SHAPE
    + "\n\nDo not include CWE identifiers, line numbers, or evidence excerpts.\n\n"
    + "File: {file_path}\n"
    + "```\n{content}\n```\n"
)


def build_cookbook_prompt(*, file_path: str, content: str) -> str:
    return COOKBOOK_PROMPT_TEMPLATE.format(
        file_path=file_path,
        content=content,
    )
