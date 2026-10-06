"""Extract secret credential values at parse time for presentation-layer redaction.

Values are attached to parse results for display indexing only — never stored in
findings or used to alter detection logic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

# Literal value replacement below this length risks false positives (e.g. "1", "7").
MIN_REDACTABLE_SECRET_LENGTH = 3

# Common English / default credential strings — literal replacement in prose is unsafe.
AMBIGUOUS_SECRET_VALUES: frozenset[str] = frozenset(
    {
        "public",
        "private",
        "cisco",
        "admin",
        "secret",
        "password",
        "manager",
        "monitor",
    }
)


def is_ambiguous_secret_value(value: str) -> bool:
    """True when a value is a common word/default and needs context-gated prose redaction."""
    return value.strip().lower() in AMBIGUOUS_SECRET_VALUES


def is_secret_shaped_for_prose(value: str) -> bool:
    """True when a value may be unconditionally redacted in prose (outside credential context).

    Heuristic (presentation-only, not used for detection):
    - Never secret-shaped if on the ambiguous English/default floor list.
    - Minimum length 6.
    - At least two character classes among lower, upper, digit, special, AND
      (length >= 8 OR contains a digit or non-alphanumeric symbol).
    - Pure alphabetic tokens shorter than 12 characters are treated as dictionary
      words and remain context-gated in prose.
    """
    if is_ambiguous_secret_value(value):
        return False
    stripped = value.strip()
    if len(stripped) < 6:
        return False
    if stripped.isalpha() and stripped.isascii() and len(stripped) < 12:
        return False
    classes: set[str] = set()
    for char in stripped:
        if char.islower():
            classes.add("lower")
        elif char.isupper():
            classes.add("upper")
        elif char.isdigit():
            classes.add("digit")
        else:
            classes.add("special")
    if len(classes) < 2:
        return False
    if len(stripped) >= 8:
        return True
    return "digit" in classes or "special" in classes


def is_secret_shaped_for_literal_redaction(value: str) -> bool:
    """Alias — same heuristic gates file-wide replacement on config lines and in prose."""
    return is_secret_shaped_for_prose(value)


@dataclass(frozen=True)
class ExtractedSecret:
    directive_id: str
    value: str
    line_no: int
    span_start: int
    span_end: int
    raw: str | None = None
    attribute: str | None = None
    context: str | None = None


@dataclass(frozen=True)
class SkippedSecretValue:
    value: str
    reason: str
    directive_id: str
    line_no: int


@dataclass(frozen=True)
class SecretValueSet:
    """Redactable secret literals plus values excluded from literal replacement."""

    redactable: frozenset[str] = frozenset()
    ambiguous: frozenset[str] = frozenset()
    extracted: tuple[ExtractedSecret, ...] = ()
    skipped: tuple[SkippedSecretValue, ...] = ()

    @staticmethod
    def empty() -> SecretValueSet:
        return SecretValueSet()

    def merge(self, other: SecretValueSet) -> SecretValueSet:
        return SecretValueSet(
            redactable=self.redactable | other.redactable,
            ambiguous=self.ambiguous | other.ambiguous,
            extracted=self.extracted + other.extracted,
            skipped=self.skipped + other.skipped,
        )

    @classmethod
    def from_parts(
        cls,
        extracted: Iterable[ExtractedSecret],
    ) -> SecretValueSet:
        redactable: set[str] = set()
        ambiguous: set[str] = set()
        skipped: list[SkippedSecretValue] = []
        items = tuple(extracted)
        for item in items:
            ok, reason = _literal_redaction_eligibility(item.value)
            if ok:
                if is_ambiguous_secret_value(item.value):
                    ambiguous.add(item.value)
                else:
                    redactable.add(item.value)
            else:
                skipped.append(
                    SkippedSecretValue(
                        value=item.value,
                        reason=reason,
                        directive_id=item.directive_id,
                        line_no=item.line_no,
                    )
                )
        return cls(
            redactable=frozenset(redactable),
            ambiguous=frozenset(ambiguous),
            extracted=items,
            skipped=tuple(skipped),
        )


def _literal_redaction_eligibility(value: str) -> tuple[bool, str]:
    stripped = value.strip()
    if not stripped:
        return False, "empty value"
    if len(stripped) < MIN_REDACTABLE_SECRET_LENGTH:
        return (
            False,
            f"value shorter than minimum length {MIN_REDACTABLE_SECRET_LENGTH} "
            "(directive-pattern redaction still applies on source lines)",
        )
    if stripped.isdigit():
        return (
            False,
            "numeric-only values are too generic for literal redaction "
            "(directive-pattern redaction still applies on source lines)",
        )
    return True, ""


# Capture patterns mirror config_redaction.py directive regexes (value = group 2).
# Each entry: (directive_id, pattern, value_group).
CREDENTIAL_BEARING_CLI_DIRECTIVES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("ios_xe.snmp-server.community", re.compile(r"^(\s*snmp-server\s+community\s+)(\S+)(.*)$", re.I), 2),
    (
        "ios_xe.snmp-server.host_community",
        re.compile(r"^(\s*snmp-server\s+host\s+\S+\s+version\s+\d+c\s+)(\S+)(.*)$", re.I),
        2,
    ),
    ("ios_xe.enable.password", re.compile(r"^(\s*enable\s+password(?:\s+\d+)?\s+)(\S+)(.*)$", re.I), 2),
    ("ios_xe.enable.secret", re.compile(r"^(\s*enable\s+secret(?:\s+\d+)?\s+)(\S+)(.*)$", re.I), 2),
    ("asa.crypto.pre_shared_key", re.compile(r"^(\s*pre-shared-key(?:\s+address)?\s+)(.+)$", re.I), 2),
    ("asa.crypto.key_string", re.compile(r"^(\s*key-string\s+)(.+)$", re.I), 2),
    ("ios_xe.aaa.server_key", re.compile(r"^(\s*(?:tacacs|radius)(?:-server)?\s+\S+\s+key(?:\s+\d+)?\s+)(.+)$", re.I), 2),
    ("ios_xe.radius_server.key", re.compile(r"^(\s*radius-server\s+key(?:\s+\d+)?\s+)(.+)$", re.I), 2),
    ("cli.username.password", re.compile(r"^(\s*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)(.+)$", re.I), 2),
    ("asa.passwd", re.compile(r"^(\s*passwd(?:\s+\d+)?\s+)(.+)$", re.I), 2),
    ("cli.ntp.authentication_key", re.compile(r"^(\s*ntp\s+authentication-key\s+\d+\s+\w+\s+)(.+)$", re.I), 2),
    ("cli.ospf.message_digest_key", re.compile(r"^(\s*(?:\w+\s+)*ospf\s+message-digest-key\s+\d+\s+\w+\s+)(.+)$", re.I), 2),
    ("cli.bgp.neighbor.password", re.compile(r"^(\s*neighbor\s+\S+\s+password(?:\s+\d+)?\s+)(.+)$", re.I), 2),
    ("nx_os.snmp-server.community", re.compile(r"^(\s*snmp-server\s+community\s+)(\S+)(.*)$", re.I), 2),
    (
        "nx_os.radius-server.key",
        re.compile(r"^(\s*radius-server\s+key(?:\s+\d+)?\s+)(.+)$", re.I),
        2,
    ),
    (
        "nx_os.username.password",
        re.compile(r"^(\s*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)(.+)$", re.I),
        2,
    ),
)

CREDENTIAL_BEARING_HCL_DIRECTIVES: tuple[str, ...] = (
    "hcl.provider.credential",
    "hcl.fmc.credential_attr",
    "hcl.variable.sensitive_default",
)

_LINE_CAPTURES = CREDENTIAL_BEARING_CLI_DIRECTIVES


def credential_bearing_directive_ids() -> tuple[str, ...]:
    """Every CLI/HCL directive whose operand may carry a credential value."""
    return tuple(item[0] for item in CREDENTIAL_BEARING_CLI_DIRECTIVES) + CREDENTIAL_BEARING_HCL_DIRECTIVES


def spans_for_line(secret_values: SecretValueSet | None, line_no: int) -> list[tuple[int, int]]:
    if secret_values is None:
        return []
    return [
        (item.span_start, item.span_end)
        for item in secret_values.extracted
        if item.line_no == line_no and item.span_end > item.span_start
    ]


def redact_line_at_spans(line: str, spans: list[tuple[int, int]], *, replacement: str = "[REDACTED]") -> str:
    if not spans:
        return line
    result = line
    for start, end in sorted(spans, key=lambda item: item[0], reverse=True):
        if start < 0 or end > len(result) or start >= end:
            continue
        result = f"{result[:start]}{replacement}{result[end:]}"
    return result

_HCL_VARIABLE_START = re.compile(r'^\s*variable\s+"([^"]+)"', re.IGNORECASE)
_HCL_SENSITIVE_NAME = re.compile(r"(?:password|secret|key|token)", re.IGNORECASE)
_HCL_SENSITIVE_ATTR = re.compile(r"^\s*sensitive\s*=\s*true\b", re.IGNORECASE)
_HCL_DEFAULT_ASSIGN = re.compile(r'^(\s*default\s*=\s*)(?:"([^"]*)"|([^\s#]+))(.*)$', re.IGNORECASE)
_HCL_PROVIDER_CRED = re.compile(r'^(\s*(?:username|password)\s*=\s*)(?:"([^"]*)"|([^\s#]+))(.*)$', re.IGNORECASE)
_HCL_FMC_ATTR = re.compile(
    r'^(\s*(?:api_key|client_secret|registration_key|shared_secret|password|username)\s*=\s*)(?:"([^"]*)"|([^\s#]+))(.*)$',
    re.IGNORECASE,
)


def _capture_cli_line(line: str, line_no: int) -> list[ExtractedSecret]:
    found: list[ExtractedSecret] = []
    for directive_id, pattern, group in _LINE_CAPTURES:
        if directive_id.startswith("hcl."):
            continue
        match = pattern.match(line)
        if not match:
            continue
        value = match.group(group).strip()
        if not value:
            continue
        found.append(
            ExtractedSecret(
                directive_id=directive_id,
                value=value,
                line_no=line_no,
                span_start=match.start(group),
                span_end=match.end(group),
                raw=line,
            )
        )
    return found


def _capture_hcl_line(
    line: str,
    line_no: int,
    *,
    in_variable: bool,
    variable_sensitive: bool,
) -> list[ExtractedSecret]:
    found: list[ExtractedSecret] = []
    for pattern, directive_id in (
        (_HCL_PROVIDER_CRED, "hcl.provider.credential"),
        (_HCL_FMC_ATTR, "hcl.fmc.credential_attr"),
    ):
        match = pattern.match(line)
        if not match:
            continue
        value = (match.group(2) or match.group(3) or "").strip()
        if value:
            value_group = 2 if match.group(2) else 3
            found.append(
                ExtractedSecret(
                    directive_id=directive_id,
                    value=value,
                    line_no=line_no,
                    span_start=match.start(value_group),
                    span_end=match.end(value_group),
                    raw=line,
                    attribute=match.group(1).strip().split("=")[0].strip(),
                )
            )
    if in_variable and variable_sensitive:
        default_match = _HCL_DEFAULT_ASSIGN.match(line)
        if default_match:
            value = (default_match.group(2) or default_match.group(3) or "").strip()
            if value:
                value_group = 2 if default_match.group(2) else 3
                found.append(
                    ExtractedSecret(
                        directive_id="hcl.variable.sensitive_default",
                        value=value,
                        line_no=line_no,
                        span_start=default_match.start(value_group),
                        span_end=default_match.end(value_group),
                        raw=line,
                        attribute="default",
                    )
                )
    return found


def _is_hcl_path(path: str | None) -> bool:
    if not path:
        return False
    lowered = path.lower()
    return lowered.endswith((".tf", ".tfvars", ".hcl"))


def extract_secret_values_from_content(content: str, *, path: str | None = None) -> SecretValueSet:
    """Scan config text and collect parser-aligned secret values."""
    extracted: list[ExtractedSecret] = []
    if _is_hcl_path(path):
        in_variable = False
        variable_sensitive = False
        brace_depth = 0
        for line_no, line in enumerate(content.splitlines(), start=1):
            if _HCL_VARIABLE_START.match(line):
                in_variable = True
                variable_sensitive = bool(
                    _HCL_SENSITIVE_NAME.search(_HCL_VARIABLE_START.match(line).group(1))
                )
                brace_depth = line.count("{") - line.count("}")
                if brace_depth <= 0 and "{" not in line:
                    brace_depth = 1
            elif in_variable:
                if _HCL_SENSITIVE_ATTR.match(line):
                    variable_sensitive = True
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0 and line.strip():
                    in_variable = False
                    variable_sensitive = False
            extracted.extend(
                _capture_hcl_line(
                    line,
                    line_no,
                    in_variable=in_variable,
                    variable_sensitive=variable_sensitive,
                )
            )
            extracted.extend(_capture_cli_line(line, line_no))
    else:
        seen_spans: set[tuple[int, int, int]] = set()
        for line_no, line in enumerate(content.splitlines(), start=1):
            for item in _capture_cli_line(line, line_no):
                span_key = (item.line_no, item.span_start, item.span_end)
                if span_key in seen_spans:
                    continue
                seen_spans.add(span_key)
                extracted.append(item)
    return SecretValueSet.from_parts(extracted)


def build_secret_value_index(file_contents: dict[str, str]) -> dict[str, SecretValueSet]:
    return {
        path: extract_secret_values_from_content(content, path=path)
        for path, content in file_contents.items()
    }


def merged_secret_values(
    index: dict[str, SecretValueSet],
    *,
    path: str | None = None,
) -> SecretValueSet:
    if path and path in index:
        return index[path]
    merged = SecretValueSet.empty()
    for item in index.values():
        merged = merged.merge(item)
    return merged
