"""Cookbook-faithful Configuration_Assessment prompt for Experiment H."""

from __future__ import annotations

COOKBOOK_FAITHFUL_PROMPT_SHAPE = (
    "You are a security auditor reviewing the configuration of a configuration file "
    "for security issues. Assess line-by-line for misconfigurations, weak settings, "
    "and missing best practices; respond with detected misconfiguration, severity, "
    "and recommended fix."
)


def build_cookbook_faithful_prompt(*, config_text: str) -> str:
    """Verbatim shape from cookbook Configuration_Assessment.ipynb (Terraform → configuration)."""
    return f"""You are a security auditor reviewing the configuration of a configuration file for security issues.

Go over the following configuration line-by-line and assess it for:
1. Security misconfigurations
2. Weak or deprecated settings
3. Missing best practices

## CONFIGURATION
{config_text}

Respond with:
- Detected misconfiguration
- Severity (Low/Medium/High)
- Recommended fix
"""
