"""Config secret redaction patterns, enumeration guard, and presentation helpers."""

from __future__ import annotations

from pathlib import Path

from shift_left.handlers.config.secret_values import (
    MIN_REDACTABLE_SECRET_LENGTH,
    SecretValueSet,
    extract_secret_values_from_content,
)
from shift_left.ui.config_redaction import (
    missing_redaction_patterns,
    redact_config_content,
    redact_config_line,
    redact_display_text,
    redact_known_values,
    redaction_pattern_ids,
    secret_bearing_directives_from_parsers,
)

ROOT = Path(__file__).resolve().parents[3]


def test_secret_bearing_directives_cover_all_parser_credentials() -> None:
    missing = missing_redaction_patterns()
    assert not missing, f"Secret-bearing directives missing redaction patterns: {sorted(missing)}"


def test_redaction_pattern_ids_match_registry() -> None:
    directives = secret_bearing_directives_from_parsers()
    pattern_ids = set(redaction_pattern_ids())
    for directive in directives:
        assert directive.redaction_pattern_id in pattern_ids, directive.directive_id


def test_cli_username_password_redacted() -> None:
    line = "username netops password 7 094F471A1A0A"
    assert redact_config_line(line) == "username netops password 7 [REDACTED]"


def test_asa_snmp_community_redacted() -> None:
    line = "snmp-server community Sup3rS3cr3tC0mm RW"
    assert redact_config_line(line) == "snmp-server community [REDACTED] RW"


def test_asa_passwd_redacted() -> None:
    line = "passwd 2KFQnbNIdI.2KYOU encrypted"
    redacted = redact_config_line(line)
    assert redacted.startswith("passwd [REDACTED]")
    assert "2KFQnbNIdI" not in redacted


def test_ntp_authentication_key_redacted() -> None:
    line = "ntp authentication-key 42 md5 NtpS3cretValue"
    assert "[REDACTED]" in redact_config_line(line)
    assert "NtpS3cretValue" not in redact_config_line(line)


def test_ospf_message_digest_key_redacted() -> None:
    line = " ip ospf message-digest-key 1 md5 OspfDigestKey"
    redacted = redact_config_line(line)
    assert "OspfDigestKey" not in redacted
    assert "[REDACTED]" in redacted


def test_bgp_neighbor_password_redacted() -> None:
    line = "neighbor 10.0.0.1 password 7 BgpSecretHash"
    redacted = redact_config_line(line)
    assert "BgpSecretHash" not in redacted
    assert "neighbor 10.0.0.1 password 7 [REDACTED]" in redacted


def test_unparsed_malformed_enable_password_line_redacted() -> None:
    line = "enable password 7 094F471A1A0A this line is deliberately malformed {{"
    redacted = redact_config_line(line)
    assert "094F471A1A0A" not in redacted
    assert "enable password 7 [REDACTED]" in redacted


def test_hcl_provider_password_redacted() -> None:
    content = """\
provider "fmc" {
  url      = "https://fmc.example"
  username = "admin"
  password = "FmcProviderSecret"
}
"""
    redacted = redact_config_content(content, path="terraform/main.tf")
    assert "FmcProviderSecret" not in redacted
    assert 'password = [REDACTED]' in redacted
    assert 'username = [REDACTED]' in redacted


def test_hcl_sensitive_variable_default_redacted() -> None:
    content = """\
variable "fmc_api_token" {
  type      = string
  sensitive = true
  default   = "token-value-should-hide"
}
"""
    redacted = redact_config_content(content, path="terraform/vars.tf")
    assert "token-value-should-hide" not in redacted
    assert 'default   = [REDACTED]' in redacted


def test_hcl_variable_name_sensitive_default_redacted() -> None:
    content = """\
variable "db_password" {
  type    = string
  default = "DbSecret123"
}
"""
    redacted = redact_config_content(content, path="terraform/vars.tf")
    assert "DbSecret123" not in redacted


def test_redact_display_text_multiline_snippet() -> None:
    snippet = "snmp-server community LeakedSecret RW\nhostname edge"
    redacted = redact_display_text(snippet, path="config/edge.cfg")
    assert "LeakedSecret" not in redacted
    assert "snmp-server community [REDACTED]" in redacted


def test_redact_display_text_snmp_prose_description() -> None:
    prose = "SNMP community 'public' is a well-known default credential."
    redacted = redact_display_text(prose)
    assert "'public'" not in redacted
    assert "SNMP community '[REDACTED]'" in redacted


def test_ambiguous_public_redacted_on_config_line() -> None:
    line = "snmp-server community public RW"
    assert redact_config_line(line) == "snmp-server community [REDACTED] RW"


def test_ambiguous_public_redacted_in_quoted_model_prose() -> None:
    config = "snmp-server community public RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    assert "public" in secrets.ambiguous
    prose = 'the community string "public" grants RW'
    redacted = redact_display_text(prose, secret_values=secrets)
    assert '"public"' not in redacted
    assert "[REDACTED]" in redacted


def test_ambiguous_public_not_redacted_in_unrelated_prose() -> None:
    config = "snmp-server community public RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    prose = "exposed to the public internet"
    redacted = redact_display_text(prose, secret_values=secrets)
    assert "public internet" in redacted


def test_ambiguous_public_not_mangled_in_publicly_routable() -> None:
    config = "snmp-server community public RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    description = "Interface is publicly routable and reachable."
    redacted = redact_display_text(description, secret_values=secrets)
    assert "publicly routable" in redacted


def test_redact_known_values_model_prose_paraphrase() -> None:
    config = "snmp-server community public RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    prose = "the community string public grants RW"
    redacted = redact_display_text(prose, secret_values=secrets)
    assert "public" not in redacted.lower().split()
    assert "[REDACTED]" in redacted


def test_redact_known_values_handler_description_quoted_secret() -> None:
    config = "snmp-server community Sup3rS3cr3tC0mm RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    description = "SNMP community 'Sup3rS3cr3tC0mm' is a weak credential."
    redacted = redact_display_text(description, secret_values=secrets)
    assert "Sup3rS3cr3tC0mm" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_known_values_diff_context_line() -> None:
    diff_context = " snmp-server community LeakedSecret RW"
    secrets = extract_secret_values_from_content(diff_context, path="config/edge.cfg")
    redacted = redact_display_text(diff_context, path="config/edge.cfg", secret_values=secrets)
    assert "LeakedSecret" not in redacted
    assert "snmp-server community [REDACTED]" in redacted


def test_short_community_string_skipped_with_explicit_reason() -> None:
    config = "snmp-server community 1 RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    assert "1" not in secrets.redactable
    assert secrets.skipped
    reason = secrets.skipped[0].reason
    assert str(MIN_REDACTABLE_SECRET_LENGTH) in reason
    assert "directive-pattern" in reason
    line_redacted = redact_config_line(config)
    assert "snmp-server community [REDACTED]" in line_redacted


def test_ambiguous_public_operand_redacts_hostname_intact() -> None:
    content = """snmp-server community public RW
hostname sw-public-01
description public-facing uplink
"""
    redacted = redact_config_content(content, path="config/edge.cfg")
    assert "snmp-server community [REDACTED] RW" in redacted
    assert "sw-public-01" in redacted
    assert "public-facing uplink" in redacted


def test_holdout_iosxe_tricky_public_hostname_renders_intact() -> None:
    path = ROOT / "validation" / "corpus" / "holdout" / "cisco_ios_xe" / "holdout-iosxe-tricky-public-hostname.cfg"
    content = path.read_text(encoding="utf-8")
    redacted = redact_config_content(content, path=str(path))
    assert "branch-public-services-sw1" in redacted
    assert "campus-nms-44a1" not in redacted
    assert "[REDACTED]" in redacted


def test_dictionary_community_network_operand_only_on_config_lines() -> None:
    content = """snmp-server community network RW
hostname network-core-01
description network uplink
"""
    secrets = extract_secret_values_from_content(content, path="config/edge.cfg")
    redacted = redact_config_content(content, path="config/edge.cfg", secret_values=secrets)
    assert "snmp-server community [REDACTED] RW" in redacted
    assert "hostname network-core-01" in redacted
    assert "description network uplink" in redacted


def test_secret_shaped_community_redacts_all_config_line_occurrences() -> None:
    content = """snmp-server community Xk9$mQ2v RW
hostname Xk9$mQ2v-core
description uses Xk9$mQ2v in remark
"""
    secrets = extract_secret_values_from_content(content, path="config/edge.cfg")
    redacted = redact_config_content(content, path="config/edge.cfg", secret_values=secrets)
    assert "Xk9$mQ2v" not in redacted
    assert redacted.count("[REDACTED]") >= 3


def test_snmp_server_host_community_redacted_by_position() -> None:
    line = "snmp-server host 10.1.1.1 version 2c public"
    secrets = extract_secret_values_from_content(line, path="config/edge.cfg")
    redacted = redact_config_line(line, line_no=1, secret_values=secrets)
    assert redacted == "snmp-server host 10.1.1.1 version 2c [REDACTED]"


def test_snmp_community_with_acl_operand_redacted_by_position() -> None:
    line = "snmp-server community public RO 10"
    secrets = extract_secret_values_from_content(line, path="config/edge.cfg")
    redacted = redact_config_line(line, line_no=1, secret_values=secrets)
    assert redacted == "snmp-server community [REDACTED] RO 10"


def test_unparsed_malformed_line_uses_pattern_fallback() -> None:
    line = "enable password 7 094F471A1A0A this line is deliberately malformed {{"
    redacted = redact_config_line(line, line_no=1, secret_values=SecretValueSet.empty())
    assert "094F471A1A0A" not in redacted
    assert "enable password 7 [REDACTED]" in redacted


def test_credential_bearing_directive_ids_match_secret_values_registry() -> None:
    from shift_left.handlers.config.secret_values import credential_bearing_directive_ids
    from shift_left.ui.config_redaction import secret_bearing_directives_from_parsers

    registry_ids = {item.directive_id for item in secret_bearing_directives_from_parsers()}
    assert set(credential_bearing_directive_ids()) == registry_ids


def test_dictionary_community_network_does_not_mangle_unrelated_prose() -> None:
    config = "snmp-server community network RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    assert "network" in secrets.redactable
    prose = "The vlan network segment failed during change window."
    redacted = redact_display_text(prose, secret_values=secrets)
    assert "vlan network segment" in redacted


def test_secret_shaped_community_redacts_in_prose_without_keyword() -> None:
    config = "snmp-server community Xk9$mQ2v RW"
    secrets = extract_secret_values_from_content(config, path="config/edge.cfg")
    prose = "Model copied Xk9$mQ2v into the ticket body."
    redacted = redact_display_text(prose, secret_values=secrets)
    assert "Xk9$mQ2v" not in redacted
    assert "[REDACTED]" in redacted


def test_secret_shaped_psk_redacts_in_url_query_string() -> None:
    secrets = extract_secret_values_from_content(
        "pre-shared-key Xk9$mQ2v",
        path="config/edge.cfg",
    )
    url = "https://host/api?key=Xk9$mQ2v&x=1"
    redacted = redact_display_text(url, secret_values=secrets)
    assert "Xk9$mQ2v" not in redacted
    assert "https://host/api?key=[REDACTED]&x=1" in redacted


def test_secret_shaped_psk_redacts_inside_base64_blob() -> None:
    secrets = extract_secret_values_from_content(
        "pre-shared-key Xk9$mQ2v",
        path="config/edge.cfg",
    )
    blob = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AXk9$mQ2vCgKCAQEA"
    redacted_prose = redact_display_text(blob, secret_values=secrets)
    redacted_config = redact_known_values(blob, secrets, prose=False)
    assert "Xk9$mQ2v" not in redacted_prose
    assert "Xk9$mQ2v" not in redacted_config
    assert "[REDACTED]" in redacted_prose
    assert "[REDACTED]" in redacted_config
