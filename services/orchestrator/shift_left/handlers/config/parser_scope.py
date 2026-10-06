"""Parser coverage globs per managed target type (structural handler scope)."""

from __future__ import annotations

from typing import Any

from shift_left.routing.globmatch import matches_any

# Extensions each managed target type's structural parser can evaluate.
TARGET_TYPE_PARSER_GLOBS: dict[str, tuple[str, ...]] = {
    "cisco_secure_firewall": ("**/*.rules", "**/*.conf"),
    "cisco_ios_xe": ("**/*.cfg", "**/*.conf", "**/*.txt"),
    "cisco_nx_os": ("**/*.cfg", "**/*.conf", "**/*.txt"),
    "cisco_ftd": ("**/*.tf", "**/*.hcl"),
    "generic_terraform": ("**/*.tf", "**/*.hcl", "**/*.tfvars"),
}

# Union of all per-target parser globs — used by CWE-284/754 blocking policies only.
BLOCKING_POLICY_PATH_GLOBS: tuple[str, ...] = tuple(
    sorted({glob for globs in TARGET_TYPE_PARSER_GLOBS.values() for glob in globs})
)

# Extensions claimable on the PR path without resolving a managed target.
# ``**/*.cfg`` is omitted — only ``cisco_ios_xe`` claims ``.cfg`` via per-target scope.
ROUTING_PARSER_CLAIM_GLOBS: tuple[str, ...] = (
    "**/*.conf",
    "**/*.hcl",
    "**/*.rules",
    "**/*.tf",
    "**/*.tfvars",
    "**/*.txt",
)

# Backward-compatible alias (blocking-policy union, not routing claim set).
DEFAULT_DETERMINISTIC_PARSER_GLOBS = BLOCKING_POLICY_PATH_GLOBS


def path_in_target_parser_scope(target_type: str, path: str) -> bool:
    globs = TARGET_TYPE_PARSER_GLOBS.get(target_type)
    if not globs:
        return False
    return matches_any(path, globs)


def path_in_routing_parser_claim_scope(path: str, routing: Any) -> bool:
    """Global PR claim globs when no managed target applies."""
    globs = routing.routing_parser_claim_globs
    return matches_any(path, globs)


def path_parser_scope_agrees_for_target(
    path: str,
    target_type: str,
    routing: Any,
) -> bool:
    """
    True when a config path is parser-scoped for ``target_type``.

    Corpus gate and target-aware PR path claim must both use this predicate.
    """
    if not matches_any(path, routing.config_globs):
        return False
    if matches_any(path, routing.pr_gate_exclusion_globs):
        return False
    return path_in_target_parser_scope(target_type, path)


def effective_routing_parser_claim_globs(routing: Any) -> tuple[str, ...]:
    return tuple(routing.routing_parser_claim_globs)
