"""Eval prompt templates and platform-specific context for Foundation-Sec."""

from __future__ import annotations

from foundation_sec_server.handlers.registry import ConfigFormatHandler

PROMPT_VARIANT_BASELINE = "baseline"
PROMPT_VARIANT_PLATFORM_SPECIFIC = "platform_specific"
PROMPT_VARIANT_PLATFORM_SPECIFIC_COLON = "platform_specific_colon"
PROMPT_VARIANT_CONSTRAINED_OUTPUT = "constrained_output"
PROMPT_VARIANT_PLATFORM_CONSTRAINED = "platform_constrained"

PLATFORM_SPECIFIC_SUFFIX_BRACKET = "Findings JSON array:\n["
PLATFORM_SPECIFIC_SUFFIX_COLON = "JSON array:"

_CONSTRAINED_OUTPUT_REQUIREMENTS = """\
CONSTRAINED OUTPUT (required for every finding):
- evidence MUST be a verbatim quote copied exactly from the config text AFTER the "|" on one or more lines (do NOT include line-number prefixes in evidence).
- line_start and line_end MUST be valid line numbers shown in the input (between {line_start} and {line_end}).
- If you cannot quote exact config text and cite a valid line, omit that finding."""

_PLATFORM_ASA_IOS = """\
Platform: Cisco ASA / IOS-XE access control configuration.
Domain facts (apply before flagging):
- Access-list entries (ACEs) are evaluated top-down; the first matching ACE wins.
- ACE syntax using "any any" means unrestricted source and destination for that permit/deny.
- `enable secret` types 5, 8, and 9 store password hashes (MD5/scrypt/SHA), not cleartext — do not flag hash format alone as a weak password.
- `no ip http server` is the hardened state (HTTP management disabled), not a defect.
- A non-default read-only SNMP community string is not by itself a security finding."""

_PLATFORM_FMC_HCL = """\
Platform: Cisco FMC policy expressed in Terraform/HCL (and related IaC in this file).
Domain facts (apply before flagging):
- `source_network_objects`, `destination_network_objects`, and similar fields reference named `fmc_network` / group objects defined elsewhere in the file — resolve object definitions before judging rule breadth.
- A rule whose sources and destinations resolve only to RFC1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) is scoped private access, not unrestricted or internet-wide (0.0.0.0/0).
- Do not treat RFC1918 private supernets alone as equivalent to public internet exposure."""

_PLATFORM_CONTEXT_BY_TARGET_TYPE: dict[str, str] = {
    "cisco_secure_firewall": _PLATFORM_ASA_IOS,
    "cisco_ios_xe": _PLATFORM_ASA_IOS,
    "cisco_ftd": _PLATFORM_FMC_HCL,
    "generic_terraform": (
        _PLATFORM_FMC_HCL
        + "\n"
        + "Also evaluate non-FMC cloud resources (AWS/Azure/GCP security groups, etc.) for internet-wide ingress (0.0.0.0/0, ::/0) and least-privilege."
    ),
}

_PLATFORM_SPECIFIC_EVAL_PROMPT = """You are Foundation-Sec, performing DEFENSIVE review of a PROPOSED configuration change.
You evaluate supplied config text ONLY — you do NOT scan or probe live infrastructure.

{platform_context}

Each config line is prefixed with its actual file line number (e.g. "   12| ..."). Use those numbers in line_start and line_end.

Return ONLY a JSON array (no markdown). Each object:
  file_path, line_start, line_end, cwe, cve_refs (array), severity (info|low|medium|high|critical),
  confidence (0.0-1.0), title, description, evidence, trace

If uncertain, use lower confidence (0.3-0.6) but still include likely concerns for human review.
If no concerns, return [].

File: {file_path}
Lines: {line_start}-{line_end}
```config
{content}
```
{suffix}"""

_PLATFORM_CONSTRAINED_EVAL_PROMPT = """You are Foundation-Sec, performing DEFENSIVE review of a PROPOSED configuration change.
You evaluate supplied config text ONLY — you do NOT scan or probe live infrastructure.

{platform_context}

Each config line is prefixed with its actual file line number (e.g. "   12| ..."). Use those numbers in line_start and line_end.

""" + _CONSTRAINED_OUTPUT_REQUIREMENTS + """

Return ONLY a JSON array (no markdown). Each object:
  file_path, line_start, line_end, cwe, cve_refs (array), severity (info|low|medium|high|critical),
  confidence (0.0-1.0), title, description, evidence, trace

If uncertain, use lower confidence (0.3-0.6) but still include likely concerns for human review.
If no concerns, return [].

File: {file_path}
Lines: {line_start}-{line_end}
```config
{content}
```
JSON array:"""

_CONSTRAINED_OUTPUT_EVAL_PROMPT = """You are Foundation-Sec, performing DEFENSIVE review of a PROPOSED configuration change.
You evaluate supplied config text ONLY — you do NOT scan or probe live infrastructure.

{format_context}

Each config line is prefixed with its actual file line number (e.g. "   12| ..."). Use those numbers in line_start and line_end.

""" + _CONSTRAINED_OUTPUT_REQUIREMENTS + """

Return ONLY a JSON array (no markdown). Each object:
  file_path, line_start, line_end, cwe, cve_refs (array), severity (info|low|medium|high|critical),
  confidence (0.0-1.0), title, description, evidence, trace

If uncertain, use lower confidence (0.3-0.6) but still include likely concerns for human review.
If no concerns, return [].

File: {file_path}
Lines: {line_start}-{line_end}
```config
{content}
```
JSON array:"""


def platform_context_for_target_type(target_type: str | None, *, handler: ConfigFormatHandler) -> str:
    if target_type and target_type in _PLATFORM_CONTEXT_BY_TARGET_TYPE:
        return _PLATFORM_CONTEXT_BY_TARGET_TYPE[target_type]
    return handler.prompt_context


def number_lines(content: str, *, line_start: int) -> str:
    """Prefix each line with its 1-based file line number for model citation anchors."""
    numbered: list[str] = []
    for offset, line in enumerate(content.splitlines()):
        numbered.append(f"{line_start + offset:5d}| {line}")
    return "\n".join(numbered)


def build_constrained_output_prompt(
    *,
    handler: ConfigFormatHandler,
    file_path: str,
    line_start: int,
    line_end: int,
    content: str,
) -> str:
    numbered_content = number_lines(content, line_start=line_start)
    return _CONSTRAINED_OUTPUT_EVAL_PROMPT.format(
        format_context=handler.prompt_context,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        content=numbered_content[:12000],
    )


def build_platform_constrained_prompt(
    *,
    handler: ConfigFormatHandler,
    target_type: str | None,
    file_path: str,
    line_start: int,
    line_end: int,
    content: str,
) -> str:
    platform_context = platform_context_for_target_type(target_type, handler=handler)
    numbered_content = number_lines(content, line_start=line_start)
    return _PLATFORM_CONSTRAINED_EVAL_PROMPT.format(
        platform_context=platform_context,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        content=numbered_content[:12000],
    )


def build_platform_specific_prompt(
    *,
    handler: ConfigFormatHandler,
    target_type: str | None,
    file_path: str,
    line_start: int,
    line_end: int,
    content: str,
    suffix: str = PLATFORM_SPECIFIC_SUFFIX_BRACKET,
) -> str:
    platform_context = platform_context_for_target_type(target_type, handler=handler)
    numbered_content = number_lines(content, line_start=line_start)
    return _PLATFORM_SPECIFIC_EVAL_PROMPT.format(
        platform_context=platform_context,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        content=numbered_content[:12000],
        suffix=suffix,
    )
