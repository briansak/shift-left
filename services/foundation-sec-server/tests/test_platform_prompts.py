"""Tests for platform-specific eval prompts."""

from __future__ import annotations

from foundation_sec_server.engine import _EVAL_PROMPT
from foundation_sec_server.handlers.registry import TERRAFORM
from foundation_sec_server.prompts import (
    PROMPT_VARIANT_PLATFORM_SPECIFIC,
    build_platform_specific_prompt,
    number_lines,
    platform_context_for_target_type,
)


def test_baseline_eval_prompt_unchanged() -> None:
    assert "format_context" in _EVAL_PROMPT
    assert "platform_context" not in _EVAL_PROMPT
    assert "line number" not in _EVAL_PROMPT.lower()


def test_number_lines_prefixes_actual_file_lines() -> None:
    numbered = number_lines("hostname jump\nno ip http server", line_start=10)
    assert numbered.splitlines()[0].startswith("   10| hostname jump")
    assert numbered.splitlines()[1].startswith("   11| no ip http server")


def test_platform_context_for_asa_includes_top_down_ace() -> None:
    context = platform_context_for_target_type("cisco_secure_firewall", handler=TERRAFORM)
    assert "top-down" in context
    assert "no ip http server" in context


def test_platform_context_for_ftd_includes_object_resolution() -> None:
    context = platform_context_for_target_type("cisco_ftd", handler=TERRAFORM)
    assert "source_network_objects" in context
    assert "RFC1918" in context


def test_platform_specific_prompt_includes_numbered_content() -> None:
    prompt = build_platform_specific_prompt(
        handler=TERRAFORM,
        target_type="cisco_ftd",
        file_path="terraform/policies/x.tf",
        line_start=3,
        line_end=4,
        content="resource \"x\" {}",
    )
    assert PROMPT_VARIANT_PLATFORM_SPECIFIC
    assert "    3| resource" in prompt
    assert "source_network_objects" in prompt
    assert prompt.rstrip().endswith("[")
    assert not prompt.rstrip().endswith(":")


def test_platform_specific_colon_suffix_matches_published_baseline() -> None:
    from foundation_sec_server.prompts import (
        PLATFORM_SPECIFIC_SUFFIX_COLON,
        PROMPT_VARIANT_PLATFORM_SPECIFIC_COLON,
        build_platform_specific_prompt,
    )

    prompt = build_platform_specific_prompt(
        handler=TERRAFORM,
        target_type="cisco_ftd",
        file_path="terraform/policies/x.tf",
        line_start=3,
        line_end=4,
        content="resource \"x\" {}",
        suffix=PLATFORM_SPECIFIC_SUFFIX_COLON,
    )
    assert PROMPT_VARIANT_PLATFORM_SPECIFIC_COLON
    assert prompt.rstrip().endswith("JSON array:")
    assert not prompt.rstrip().endswith("[")


def test_constrained_output_prompt_requires_verbatim_evidence() -> None:
    from foundation_sec_server.prompts import (
        PROMPT_VARIANT_CONSTRAINED_OUTPUT,
        build_constrained_output_prompt,
    )

    prompt = build_constrained_output_prompt(
        handler=TERRAFORM,
        file_path="terraform/policies/x.tf",
        line_start=1,
        line_end=2,
        content="action = \"ALLOW\"",
    )
    assert PROMPT_VARIANT_CONSTRAINED_OUTPUT
    assert "verbatim" in prompt.lower()
    assert "    1| action" in prompt
    assert "format_context" not in prompt
    assert TERRAFORM.prompt_context.splitlines()[0] in prompt


def test_platform_constrained_prompt_combines_platform_context_and_evidence_rules() -> None:
    from foundation_sec_server.prompts import (
        PROMPT_VARIANT_PLATFORM_CONSTRAINED,
        build_platform_constrained_prompt,
    )

    prompt = build_platform_constrained_prompt(
        handler=TERRAFORM,
        target_type="cisco_ftd",
        file_path="terraform/policies/x.tf",
        line_start=2,
        line_end=3,
        content="source_network_objects = [\"fmc_network.inside\"]",
    )
    assert PROMPT_VARIANT_PLATFORM_CONSTRAINED
    assert "verbatim" in prompt.lower()
    assert "source_network_objects" in prompt
    assert "    2| source_network_objects" in prompt
