"""Presentation-layer redaction for device config secrets.

Patterns are derived from parser recognition logic (same token positions the
structural parsers use to extract credential-bearing directives). Values are
replaced with ``[REDACTED]``; directives and finding line context are preserved.

Every UI surface that renders config-derived text must call :func:`redact_config_line`
or :func:`redact_config_content` before display. Stored config, parser input, and
finding records are never modified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from shift_left.handlers.config.secret_values import (
    AMBIGUOUS_SECRET_VALUES,
    SecretValueSet,
    is_ambiguous_secret_value,
    is_secret_shaped_for_literal_redaction,
    is_secret_shaped_for_prose,
    redact_line_at_spans,
    spans_for_line,
)

_REDACTED = "[REDACTED]"

_SENSITIVE_VARIABLE_NAME = re.compile(r"(?:password|secret|key|token)", re.IGNORECASE)
_HCL_VARIABLE_START = re.compile(r'^\s*variable\s+"([^"]+)"', re.IGNORECASE)
_HCL_SENSITIVE_ATTR = re.compile(r"^\s*sensitive\s*=\s*true\b", re.IGNORECASE)
_HCL_DEFAULT_ASSIGN = re.compile(
    r'^(\s*default\s*=\s*)(?:"[^"]*"|[^\s#]+)(.*)$',
    re.IGNORECASE,
)
_HCL_PROVIDER_CREDENTIAL = re.compile(
    r'^(\s*(?:username|password)\s*=\s*)(?:"[^"]*"|[^\s#]+)(.*)$',
    re.IGNORECASE,
)
_HCL_FMC_CREDENTIAL_ATTR = re.compile(
    r'^(\s*(?:api_key|client_secret|registration_key|shared_secret|password|username)\s*=\s*)(?:"[^"]*"|[^\s#]+)(.*)$',
    re.IGNORECASE,
)
_HCL_SENSITIVE_ATTR_VALUE = re.compile(
    r'^(\s*(\w+)\s*=\s*)(?:"[^"]*"|[^\s#]+)(.*)$',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ConfigRedactionPattern:
    pattern_id: str
    parser_source: str
    description: str
    apply: Callable[[str], str]


@dataclass(frozen=True)
class SecretBearingDirective:
    """A parser-recognized directive that carries a secret value."""

    directive_id: str
    parser_source: str
    description: str
    redaction_pattern_id: str


def _replace_match(match: re.Match[str], *, value_group: int = 2) -> str:
    parts = list(match.groups())
    if len(parts) >= value_group:
        parts[value_group - 1] = _REDACTED
    return "".join(parts)


def _line_redactor(pattern: re.Pattern[str], *, value_group: int = 2) -> Callable[[str], str]:
    def _apply(line: str) -> str:
        def _sub(m: re.Match[str]) -> str:
            return _replace_match(m, value_group=value_group)

        return pattern.sub(_sub, line, count=1)

    return _apply


# ios_xe.parser._parse_snmp_community — tokens[2] is the community string
_IOS_XE_SNMP_COMMUNITY = re.compile(
    r"^(\s*snmp-server\s+community\s+)(\S+)(.*)$",
    re.IGNORECASE,
)
_IOS_XE_SNMP_HOST_COMMUNITY = re.compile(
    r"^(\s*snmp-server\s+host\s+\S+\s+version\s+\d+c\s+)(\S+)(.*)$",
    re.IGNORECASE,
)

# ios_xe.parser._apply_global_security_line — enable password / enable secret
_IOS_XE_ENABLE_PASSWORD = re.compile(
    r"^(\s*enable\s+password(?:\s+\d+)?\s+)(.+)$",
    re.IGNORECASE,
)
_IOS_XE_ENABLE_SECRET = re.compile(
    r"^(\s*enable\s+secret(?:\s+\d+)?\s+)(.+)$",
    re.IGNORECASE,
)

# ASA / IOS-XE crypto and VPN key directives (body lines inside crypto blocks)
_CRYPTO_PRE_SHARED_KEY = re.compile(
    r"^(\s*pre-shared-key(?:\s+address)?\s+)(.+)$",
    re.IGNORECASE,
)
_CRYPTO_KEY_STRING = re.compile(
    r"^(\s*key-string\s+)(.+)$",
    re.IGNORECASE,
)

# AAA / management server shared secrets (common CLI forms)
_AAA_SERVER_KEY = re.compile(
    r"^(\s*(?:tacacs|radius)(?:-server)?\s+\S+\s+key(?:\s+\d+)?\s+)(.+)$",
    re.IGNORECASE,
)
_RADIUS_SERVER_KEY = re.compile(
    r"^(\s*radius-server\s+key(?:\s+\d+)?\s+)(.+)$",
    re.IGNORECASE,
)

# Local-user and routing-protocol credentials (CLI presentation patterns)
_CLI_USERNAME_PASSWORD = re.compile(
    r"^(\s*username\s+\S+\s+(?:password|secret)(?:\s+\d+)?\s+)(.+)$",
    re.IGNORECASE,
)
_ASA_PASSWD = re.compile(
    r"^(\s*passwd(?:\s+\d+)?\s+)(.+)$",
    re.IGNORECASE,
)
_NTP_AUTH_KEY = re.compile(
    r"^(\s*ntp\s+authentication-key\s+\d+\s+\w+\s+)(.+)$",
    re.IGNORECASE,
)
_OSPF_MESSAGE_DIGEST_KEY = re.compile(
    r"^(\s*(?:\w+\s+)*ospf\s+message-digest-key\s+\d+\s+\w+\s+)(.+)$",
    re.IGNORECASE,
)
_BGP_NEIGHBOR_PASSWORD = re.compile(
    r"^(\s*neighbor\s+\S+\s+password(?:\s+\d+)?\s+)(.+)$",
    re.IGNORECASE,
)
_SNMP_COMMUNITY_QUOTED_IN_PROSE = re.compile(
    r"(SNMP community\s+['\"])([^'\"]+)(['\"])",
    re.IGNORECASE,
)
_SNMP_COMMUNITY_EMBEDDED_IN_PROSE = re.compile(
    r"(snmp-server\s+community\s+)(\S+)",
    re.IGNORECASE,
)

FINDING_CONFIG_TEXT_FIELDS: frozenset[str] = frozenset(
    {
        "evidence",
        "description",
        "model_context",
    }
)

PARSER_DERIVED_REDACTION_PATTERNS: tuple[ConfigRedactionPattern, ...] = (
    ConfigRedactionPattern(
        pattern_id="ios_xe_snmp_community",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser._parse_snmp_community",
        description="snmp-server community <value> (IOS-XE and ASA)",
        apply=_line_redactor(_IOS_XE_SNMP_COMMUNITY),
    ),
    ConfigRedactionPattern(
        pattern_id="ios_xe_snmp_host_community",
        parser_source="shift_left.handlers.config.secret_values (snmp-server host operand)",
        description="snmp-server host <addr> version 2c <community>",
        apply=_line_redactor(_IOS_XE_SNMP_HOST_COMMUNITY),
    ),
    ConfigRedactionPattern(
        pattern_id="ios_xe_enable_password",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser._apply_global_security_line",
        description="enable password [7] <value>",
        apply=_line_redactor(_IOS_XE_ENABLE_PASSWORD),
    ),
    ConfigRedactionPattern(
        pattern_id="ios_xe_enable_secret",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser._apply_global_security_line",
        description="enable secret [5|8|9] <value>",
        apply=_line_redactor(_IOS_XE_ENABLE_SECRET),
    ),
    ConfigRedactionPattern(
        pattern_id="crypto_pre_shared_key",
        parser_source="shift_left.handlers.config.parsers.asa.parser (crypto block body)",
        description="pre-shared-key <value>",
        apply=_line_redactor(_CRYPTO_PRE_SHARED_KEY),
    ),
    ConfigRedactionPattern(
        pattern_id="crypto_key_string",
        parser_source="shift_left.handlers.config.parsers.asa.parser (crypto block body)",
        description="key-string <value>",
        apply=_line_redactor(_CRYPTO_KEY_STRING),
    ),
    ConfigRedactionPattern(
        pattern_id="aaa_server_key",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser (AAA lines)",
        description="tacacs|radius server key <value>",
        apply=_line_redactor(_AAA_SERVER_KEY),
    ),
    ConfigRedactionPattern(
        pattern_id="radius_server_key",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser (AAA lines)",
        description="radius-server key <value>",
        apply=_line_redactor(_RADIUS_SERVER_KEY),
    ),
    ConfigRedactionPattern(
        pattern_id="cli_username_password",
        parser_source="Cisco IOS/ASA local-user lines (username … password|secret)",
        description="username <name> password|secret [type] <value>",
        apply=_line_redactor(_CLI_USERNAME_PASSWORD),
    ),
    ConfigRedactionPattern(
        pattern_id="asa_passwd",
        parser_source="Cisco ASA login passwd directive",
        description="passwd [encrypted] <value>",
        apply=_line_redactor(_ASA_PASSWD),
    ),
    ConfigRedactionPattern(
        pattern_id="ntp_authentication_key",
        parser_source="Cisco IOS/ASA NTP authentication-key",
        description="ntp authentication-key <id> <md5|sha1> <value>",
        apply=_line_redactor(_NTP_AUTH_KEY),
    ),
    ConfigRedactionPattern(
        pattern_id="ospf_message_digest_key",
        parser_source="Cisco IOS/ASA OSPF interface authentication",
        description="ospf message-digest-key <id> <md5|sha1> <value>",
        apply=_line_redactor(_OSPF_MESSAGE_DIGEST_KEY),
    ),
    ConfigRedactionPattern(
        pattern_id="bgp_neighbor_password",
        parser_source="Cisco IOS/ASA BGP neighbor authentication",
        description="neighbor <ip> password [type] <value>",
        apply=_line_redactor(_BGP_NEIGHBOR_PASSWORD),
    ),
    ConfigRedactionPattern(
        pattern_id="hcl_provider_credential",
        parser_source="terraform_hcl provider blocks (username/password attributes)",
        description='provider block username = "…" / password = "…"',
        apply=_line_redactor(_HCL_PROVIDER_CREDENTIAL),
    ),
    ConfigRedactionPattern(
        pattern_id="hcl_fmc_credential_attr",
        parser_source="terraform_hcl fmc_* resource credential attributes",
        description="fmc_* password|username|api_key|client_secret|registration_key|shared_secret",
        apply=_line_redactor(_HCL_FMC_CREDENTIAL_ATTR),
    ),
    ConfigRedactionPattern(
        pattern_id="hcl_variable_sensitive_default",
        parser_source="terraform_hcl variable blocks (sensitive name or sensitive=true)",
        description='variable "<*password|secret|key|token*>" default = "…" or sensitive = true',
        apply=lambda line: line,
    ),
    ConfigRedactionPattern(
        pattern_id="hcl_sensitive_attribute",
        parser_source="terraform_hcl attributes explicitly marked sensitive",
        description="attribute assignment on lines following sensitive metadata",
        apply=lambda line: line,
    ),
)

# Parser-recognized secret-bearing directives. Every entry must map to a pattern
# in PARSER_DERIVED_REDACTION_PATTERNS (enforced by tests).
SECRET_BEARING_DIRECTIVES: tuple[SecretBearingDirective, ...] = (
    SecretBearingDirective(
        directive_id="ios_xe.snmp-server.community",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser._parse_snmp_community",
        description="snmp-server community <value>",
        redaction_pattern_id="ios_xe_snmp_community",
    ),
    SecretBearingDirective(
        directive_id="ios_xe.snmp-server.host_community",
        parser_source="shift_left.handlers.config.secret_values (snmp-server host operand)",
        description="snmp-server host <addr> version 2c <community>",
        redaction_pattern_id="ios_xe_snmp_host_community",
    ),
    SecretBearingDirective(
        directive_id="ios_xe.enable.password",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser._apply_global_security_line",
        description="enable password <value>",
        redaction_pattern_id="ios_xe_enable_password",
    ),
    SecretBearingDirective(
        directive_id="ios_xe.enable.secret",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser._apply_global_security_line",
        description="enable secret <value>",
        redaction_pattern_id="ios_xe_enable_secret",
    ),
    SecretBearingDirective(
        directive_id="asa.crypto.pre_shared_key",
        parser_source="shift_left.handlers.config.parsers.asa.parser (crypto block body)",
        description="pre-shared-key <value>",
        redaction_pattern_id="crypto_pre_shared_key",
    ),
    SecretBearingDirective(
        directive_id="asa.crypto.key_string",
        parser_source="shift_left.handlers.config.parsers.asa.parser (crypto block body)",
        description="key-string <value>",
        redaction_pattern_id="crypto_key_string",
    ),
    SecretBearingDirective(
        directive_id="ios_xe.aaa.server_key",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser (AAA lines)",
        description="tacacs|radius server key <value>",
        redaction_pattern_id="aaa_server_key",
    ),
    SecretBearingDirective(
        directive_id="ios_xe.radius_server.key",
        parser_source="shift_left.handlers.config.parsers.ios_xe.parser (AAA lines)",
        description="radius-server key <value>",
        redaction_pattern_id="radius_server_key",
    ),
    SecretBearingDirective(
        directive_id="cli.username.password",
        parser_source="Cisco IOS/ASA local-user configuration",
        description="username <name> password|secret <value>",
        redaction_pattern_id="cli_username_password",
    ),
    SecretBearingDirective(
        directive_id="asa.passwd",
        parser_source="Cisco ASA passwd directive",
        description="passwd <value>",
        redaction_pattern_id="asa_passwd",
    ),
    SecretBearingDirective(
        directive_id="cli.ntp.authentication_key",
        parser_source="Cisco IOS/ASA NTP authentication-key",
        description="ntp authentication-key <id> <algo> <value>",
        redaction_pattern_id="ntp_authentication_key",
    ),
    SecretBearingDirective(
        directive_id="cli.ospf.message_digest_key",
        parser_source="Cisco IOS/ASA OSPF message-digest-key",
        description="ospf message-digest-key <id> <algo> <value>",
        redaction_pattern_id="ospf_message_digest_key",
    ),
    SecretBearingDirective(
        directive_id="cli.bgp.neighbor.password",
        parser_source="Cisco IOS/ASA BGP neighbor password",
        description="neighbor <ip> password <value>",
        redaction_pattern_id="bgp_neighbor_password",
    ),
    SecretBearingDirective(
        directive_id="hcl.provider.credential",
        parser_source="shift_left.handlers.config.parsers.terraform_hcl (provider blocks)",
        description="provider username/password attributes",
        redaction_pattern_id="hcl_provider_credential",
    ),
    SecretBearingDirective(
        directive_id="hcl.variable.sensitive_default",
        parser_source="shift_left.handlers.config.parsers.terraform_hcl (variable blocks)",
        description="variable default when name or block is sensitive",
        redaction_pattern_id="hcl_variable_sensitive_default",
    ),
    SecretBearingDirective(
        directive_id="hcl.fmc.credential_attr",
        parser_source="shift_left.handlers.config.parsers.ftd.parser (fmc_* resources)",
        description="fmc_* credential-bearing attributes",
        redaction_pattern_id="hcl_fmc_credential_attr",
    ),
    SecretBearingDirective(
        directive_id="nx_os.snmp-server.community",
        parser_source="shift_left.handlers.config.parsers.nx_os.parser._parse_snmp_community",
        description="snmp-server community <value> (NX-OS)",
        redaction_pattern_id="ios_xe_snmp_community",
    ),
    SecretBearingDirective(
        directive_id="nx_os.radius-server.key",
        parser_source="shift_left.handlers.config.parsers.nx_os.parser (AAA lines)",
        description="radius-server key <value> (NX-OS)",
        redaction_pattern_id="radius_server_key",
    ),
    SecretBearingDirective(
        directive_id="nx_os.username.password",
        parser_source="shift_left.handlers.config.parsers.nx_os.parser (username lines)",
        description="username <name> password|secret <value> (NX-OS)",
        redaction_pattern_id="cli_username_password",
    ),
)


def secret_bearing_directives_from_parsers() -> tuple[SecretBearingDirective, ...]:
    """Return the canonical list of parser-recognized secret-bearing directives."""
    return SECRET_BEARING_DIRECTIVES


def missing_redaction_patterns() -> frozenset[str]:
    """Directive ids that lack a registered redaction pattern."""
    pattern_ids = {item.pattern_id for item in PARSER_DERIVED_REDACTION_PATTERNS}
    missing: set[str] = set()
    for directive in SECRET_BEARING_DIRECTIVES:
        if directive.redaction_pattern_id not in pattern_ids:
            missing.add(directive.directive_id)
    return frozenset(missing)


def _is_hcl_path(path: str | None) -> bool:
    if not path:
        return False
    lowered = path.lower()
    return lowered.endswith((".tf", ".tfvars", ".hcl"))


class HclRedactionState:
    """Track Terraform/HCL block context for sensitive variable defaults."""

    def __init__(self) -> None:
        self._in_variable = False
        self._variable_sensitive_name = False
        self._variable_marked_sensitive = False
        self._brace_depth = 0
        self._pending_sensitive_attrs: set[str] = set()

    def redact_line(
        self,
        line: str,
        *,
        line_no: int = 1,
        secret_values: SecretValueSet | Iterable[str] | None = None,
    ) -> str:
        self._update_variable_state(line)
        redacted = redact_config_line(
            line,
            line_no=line_no,
            secret_values=secret_values,
            apply_cli_patterns=False,
        )
        redacted = _HCL_PROVIDER_CREDENTIAL.sub(
            lambda m: f"{m.group(1)}{_REDACTED}{m.group(2)}",
            redacted,
            count=1,
        )
        redacted = _HCL_FMC_CREDENTIAL_ATTR.sub(
            lambda m: f"{m.group(1)}{_REDACTED}{m.group(2)}",
            redacted,
            count=1,
        )
        if self._in_variable and (
            self._variable_sensitive_name or self._variable_marked_sensitive
        ):
            redacted = _HCL_DEFAULT_ASSIGN.sub(
                lambda m: f"{m.group(1)}{_REDACTED}{m.group(2)}",
                redacted,
                count=1,
            )
        if self._pending_sensitive_attrs:
            match = _HCL_SENSITIVE_ATTR_VALUE.match(redacted)
            if match and match.group(2).lower() in self._pending_sensitive_attrs:
                redacted = f"{match.group(1)}{_REDACTED}{match.group(3)}"
        return redacted

    def _update_variable_state(self, line: str) -> None:
        stripped = line.strip()
        if _HCL_VARIABLE_START.match(line):
            self._in_variable = True
            self._variable_marked_sensitive = False
            name_match = _HCL_VARIABLE_START.match(line)
            var_name = name_match.group(1) if name_match else ""
            self._variable_sensitive_name = bool(_SENSITIVE_VARIABLE_NAME.search(var_name))
            self._brace_depth = line.count("{") - line.count("}")
            if self._brace_depth <= 0 and "{" not in line:
                self._brace_depth = 1
            return
        if self._in_variable:
            if _HCL_SENSITIVE_ATTR.match(line):
                self._variable_marked_sensitive = True
            self._brace_depth += line.count("{") - line.count("}")
            if self._brace_depth <= 0 and stripped:
                self._in_variable = False
                self._variable_sensitive_name = False
                self._variable_marked_sensitive = False
        if re.search(r"\bsensitive\s*=\s*true\b", line, re.IGNORECASE):
            if self._in_variable:
                self._variable_marked_sensitive = True
            else:
                attr_match = re.match(r"^\s*(\w+)\s*=", line)
                if attr_match and attr_match.group(1).lower() != "sensitive":
                    self._pending_sensitive_attrs.add(attr_match.group(1).lower())


def _redact_secret_shaped_literal(text: str, value: str) -> str:
    """Replace every occurrence of a high-entropy secret literal (substring match)."""
    if not value:
        return text
    return re.sub(re.escape(value), _REDACTED, text, flags=re.IGNORECASE)


def redact_known_values(
    text: str,
    secret_values: SecretValueSet | Iterable[str] | None,
    *,
    prose: bool = False,
) -> str:
    """Replace known secret literals before directive-pattern redaction.

    Config lines (``prose=False``):
    - Operand positions from :attr:`SecretValueSet.extracted` spans are redacted
      directly when ``line_no`` is provided.
    - Secret-shaped unambiguous values may still be replaced file-wide (substring).
    - Non-secret-shaped and ambiguous values are operand-only (no file-wide replace).
    - CLI directive patterns apply only when no extracted span exists for the line
      (unparsed / fallback).

    Prose (``prose=True``):
    - Ambiguous-floor values (``AMBIGUOUS_SECRET_VALUES``): context-gated only.
    - Other values: context-gated unless they pass :func:`is_secret_shaped_for_prose`,
      in which case they may be replaced unconditionally (substring).
    """
    if not secret_values:
        return text
    if isinstance(secret_values, SecretValueSet):
        unambiguous = secret_values.redactable
        ambiguous = secret_values.ambiguous
    else:
        values = frozenset(secret_values)
        unambiguous = frozenset(item for item in values if not is_ambiguous_secret_value(item))
        ambiguous = frozenset(item for item in values if is_ambiguous_secret_value(item))
    if not unambiguous and not ambiguous:
        return text
    result = text
    if prose:
        for value in sorted(unambiguous | ambiguous, key=len, reverse=True):
            if not value:
                continue
            if is_ambiguous_secret_value(value) or not is_secret_shaped_for_prose(value):
                result = _redact_value_in_prose_context(result, value)
            else:
                result = _redact_secret_shaped_literal(result, value)
    else:
        value_set = secret_values if isinstance(secret_values, SecretValueSet) else None
        literals = unambiguous
        if value_set is not None:
            literals = value_set.redactable
        elif not isinstance(secret_values, SecretValueSet):
            literals = unambiguous
        for value in sorted(literals, key=len, reverse=True):
            if not value or not is_secret_shaped_for_literal_redaction(value):
                continue
            result = _redact_secret_shaped_literal(result, value)
    return result


def _redact_value_in_prose_context(text: str, value: str) -> str:
    escaped = re.escape(value)
    for quote in ('"', "'", "`"):
        text = re.sub(
            rf"{quote}{escaped}{quote}",
            f"{quote}{_REDACTED}{quote}",
            text,
            flags=re.IGNORECASE,
        )
    text = re.sub(
        rf"(?i)\b((?:community|password|secret|key|psk)(?:\s+\w+){{0,4}}\s+)"
        rf"(?<![\w$@./-]){escaped}(?![\w$@./-])",
        lambda match: f"{match.group(1)}{_REDACTED}",
        text,
    )
    return text


def _redact_ambiguous_value_in_prose(text: str, value: str) -> str:
    """Backward-compatible alias for ambiguous-floor context gating."""
    return _redact_value_in_prose_context(text, value)


def _apply_cli_pattern_fallback(line: str) -> str:
    redacted = line
    for item in PARSER_DERIVED_REDACTION_PATTERNS:
        if item.pattern_id in {"hcl_variable_sensitive_default", "hcl_sensitive_attribute"}:
            continue
        if item.pattern_id.startswith("hcl_"):
            continue
        redacted = item.apply(redacted)
    return redacted


def redact_config_line(
    line: str,
    *,
    line_no: int | None = None,
    secret_values: SecretValueSet | Iterable[str] | None = None,
    apply_cli_patterns: bool = True,
) -> str:
    value_set = secret_values if isinstance(secret_values, SecretValueSet) else None
    spans: list[tuple[int, int]] = []
    if value_set is not None and line_no is not None:
        spans = spans_for_line(value_set, line_no)
    had_span_redaction = bool(spans)
    redacted = redact_line_at_spans(line, spans, replacement=_REDACTED) if had_span_redaction else line
    redacted = redact_known_values(redacted, secret_values, prose=False)
    if apply_cli_patterns and not had_span_redaction:
        redacted = _apply_cli_pattern_fallback(redacted)
    return redacted


def redact_config_content(
    content: str,
    *,
    path: str | None = None,
    secret_values: SecretValueSet | Iterable[str] | None = None,
) -> str:
    if _is_hcl_path(path):
        state = HclRedactionState()
        return "\n".join(
            state.redact_line(line, line_no=index, secret_values=secret_values)
            for index, line in enumerate(content.splitlines(), start=1)
        )
    return "\n".join(
        redact_config_line(line, line_no=index, secret_values=secret_values)
        for index, line in enumerate(content.splitlines(), start=1)
    )


def redact_display_text(
    text: str,
    *,
    path: str | None = None,
    secret_values: SecretValueSet | Iterable[str] | None = None,
) -> str:
    """Redact config-derived secrets in arbitrary display text (snippets, JSON payloads)."""
    redacted = redact_known_values(text, secret_values, prose=True)
    if "\n" in redacted:
        redacted = redact_config_content(redacted, path=path, secret_values=secret_values)
    elif _looks_like_config_directive(redacted):
        redacted = redact_config_line(redacted, line_no=1, secret_values=secret_values)
    for value in sorted(AMBIGUOUS_SECRET_VALUES, key=len, reverse=True):
        redacted = _redact_ambiguous_value_in_prose(redacted, value)
    redacted = _SNMP_COMMUNITY_EMBEDDED_IN_PROSE.sub(
        lambda match: f"{match.group(1)}{_REDACTED}",
        redacted,
    )
    return _SNMP_COMMUNITY_QUOTED_IN_PROSE.sub(
        lambda match: f"{match.group(1)}{_REDACTED}{match.group(3)}",
        redacted,
    )


def _looks_like_config_directive(line: str) -> bool:
    stripped = line.lstrip()
    if not stripped:
        return False
    lowered = stripped.lower()
    prefixes = (
        "snmp-server ",
        "enable ",
        "username ",
        "passwd",
        "radius-server ",
        "tacacs",
        "pre-shared-key",
        "key-string",
        "neighbor ",
        "ntp authentication-key",
        "password ",
        "provider ",
        "variable ",
    )
    return any(lowered.startswith(prefix) for prefix in prefixes)


def redact_prose_secrets(
    text: str,
    *,
    path: str | None = None,
    secret_values: SecretValueSet | Iterable[str] | None = None,
) -> str:
    """Alias for :func:`redact_display_text` (includes handler-description prose patterns)."""
    return redact_display_text(text, path=path, secret_values=secret_values)


def redact_finding_for_display(
    finding: Any,
    *,
    path: str | None = None,
    secret_values: SecretValueSet | Iterable[str] | None = None,
) -> Any:
    """Return a copy of ``finding`` with presentation fields redacted (store unchanged)."""
    from shift_left.models.schema import Finding

    file_path = path or getattr(finding, "file_path", None)
    updates: dict[str, Any] = {}
    for field in FINDING_CONFIG_TEXT_FIELDS:
        value = getattr(finding, field, None)
        if value:
            updates[field] = redact_display_text(
                str(value),
                path=file_path,
                secret_values=secret_values,
            )
    actions = getattr(finding, "recommended_actions", None) or []
    if actions:
        updates["recommended_actions"] = [
            redact_display_text(str(item), path=file_path, secret_values=secret_values)
            for item in actions
        ]
    if not updates:
        return finding
    if isinstance(finding, Finding):
        return finding.model_copy(update=updates)
    if isinstance(finding, dict):
        merged = dict(finding)
        merged.update(updates)
        return merged
    return finding


def redact_findings_for_display(findings: list[Any]) -> list[Any]:
    return [redact_finding_for_display(item) for item in findings]


def redaction_pattern_ids() -> tuple[str, ...]:
    return tuple(item.pattern_id for item in PARSER_DERIVED_REDACTION_PATTERNS)
