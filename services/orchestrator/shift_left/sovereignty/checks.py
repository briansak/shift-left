"""Startup self-checks for sovereignty and required local assets."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from shift_left.config import AppConfig

_T = TypeVar("_T")


def _run_async(coro: Coroutine[object, object, _T]) -> _T:
    """Run a coroutine from sync code, including inside a running event loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


@dataclass
class CheckResult:
    name: str
    ok: bool
    message: str


def check_required_assets(config: AppConfig) -> list[CheckResult]:
    results: list[CheckResult] = []
    for asset in config.sovereignty.required_assets:
        path = Path(asset["path"])
        if path.exists():
            results.append(
                CheckResult(
                    name=f"asset:{path}",
                    ok=True,
                    message=f"Present: {asset.get('description', path)}",
                )
            )
        else:
            results.append(
                CheckResult(
                    name=f"asset:{path}",
                    ok=False,
                    message=(
                        f"Missing required asset at {path}. "
                        f"{asset.get('description', 'Pre-stage this path before starting.')}"
                    ),
                )
            )
    return results


def check_findings_store_path(config: AppConfig) -> CheckResult:
    path = Path(config.findings_store.sqlite_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return CheckResult(
        name="findings_store",
        ok=True,
        message=f"Findings store directory ready: {path.parent}",
    )


def check_git_token(config: AppConfig) -> CheckResult:
    token_env = config.git.token_env_name()
    if config.git.token():
        return CheckResult(
            name="git_token",
            ok=True,
            message=f"Git API token configured ({token_env}) for backend '{config.git.backend.value}'",
        )
    return CheckResult(
        name="git_token",
        ok=False,
        message=(
            f"Missing git API token. Set env var {token_env} for backend "
            f"'{config.git.backend.value}'."
        ),
    )


def check_git_sovereignty(config: AppConfig) -> CheckResult:
    git = config.git
    if git.is_sovereign():
        return CheckResult(
            name="git_sovereignty",
            ok=True,
            message=(
                "Bundled local git server (customer repos on-host). "
                "Distinct from GitHub, which hosts this tool's source only."
            ),
        )
    if git.external_sovereignty_acknowledged:
        return CheckResult(
            name="git_sovereignty",
            ok=True,
            message=(
                f"Non-sovereign git backend '{git.backend.value}' acknowledged — "
                "customer diffs and PR comments transit external infrastructure. "
                "See docs/git-backends.md."
            ),
        )
    return CheckResult(
        name="git_sovereignty",
        ok=False,
        message=(
            f"Backend '{git.backend.value}' requires git.external_sovereignty_acknowledged: true. "
            "See docs/git-backends.md for tradeoffs."
        ),
    )


def check_egress_blocked(config: AppConfig) -> CheckResult:
    """
    Best-effort runtime egress probe for sovereign bundled-git deployments.

    Skipped when an external git backend is configured (orchestrator must reach
    that provider's API at review time).
    """
    if not config.git.is_sovereign():
        return CheckResult(
            name="deny_egress",
            ok=True,
            message=(
                "Egress probe skipped — external git backend requires API access at runtime. "
                "Full runtime sovereignty is not available with github/gitlab backends."
            ),
        )

    import os

    from shift_left_shared.network import run_egress_probe

    if os.environ.get("SHIFT_LEFT_SKIP_EGRESS_PROBE", "").lower() in {"1", "true", "yes"}:
        return CheckResult(
            name="deny_egress",
            ok=True,
            message="Egress probe skipped (SHIFT_LEFT_SKIP_EGRESS_PROBE set — local dev only).",
        )

    result = run_egress_probe()
    if not result.ok:
        return CheckResult(name="deny_egress", ok=False, message=result.message)
    return CheckResult(name="deny_egress", ok=True, message=result.message)


def check_no_telemetry_config(config: AppConfig) -> CheckResult:
    if config.distribution.telemetry:
        return CheckResult(
            name="no_telemetry",
            ok=False,
            message="telemetry must be absent — this project ships no analytics or phone-home",
        )
    if config.distribution.auto_update:
        return CheckResult(
            name="no_auto_update",
            ok=False,
            message="auto_update must be false — updates are operator-initiated only",
        )
    return CheckResult(
        name="no_telemetry",
        ok=True,
        message="No telemetry, auto-update, or license phone-home (absent by design)",
    )


def check_policy_config(config: AppConfig) -> CheckResult:
    from shift_left.policy.loader import PolicyValidationError, load_and_validate_policies

    try:
        policies = load_and_validate_policies(config.policy)
    except PolicyValidationError as exc:
        return CheckResult(name="policy_config", ok=False, message=str(exc))
    return CheckResult(
        name="policy_config",
        ok=True,
        message=f"{len(policies)} policy rule(s) validated (ordered precedence, fail-loud on load)",
    )


def check_gate_branch_protection(config: AppConfig) -> CheckResult:
    gate = config.gate
    if not gate.warn_if_branch_protection_missing:
        return CheckResult(
            name="gate_branch_protection",
            ok=True,
            message="Branch protection self-check disabled (gate.warn_if_branch_protection_missing=false)",
        )
    if not gate.check_repo:
        return CheckResult(
            name="gate_branch_protection",
            ok=False,
            message=(
                "Configure gate.check_repo (owner/repo) to verify Forgejo branch protection "
                f"requires status check '{gate.status_context}' on '{gate.protected_branch}'."
            ),
        )

    from shift_left.git.factory import create_git_backend

    owner, _, repo_name = gate.check_repo.partition("/")
    if not repo_name:
        return CheckResult(
            name="gate_branch_protection",
            ok=False,
            message=f"Invalid gate.check_repo slug: {gate.check_repo!r}",
        )

    async def _probe() -> bool | None:
        backend = create_git_backend(config)
        return await backend.branch_protection_requires_status_check(
            owner,
            repo_name,
            gate.protected_branch,
            gate.status_context,
        )

    try:
        configured = _run_async(_probe())
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            name="gate_branch_protection",
            ok=False,
            message=(
                f"Could not verify branch protection for {gate.check_repo}@{gate.protected_branch}: {exc}"
            ),
        )

    if configured is True:
        return CheckResult(
            name="gate_branch_protection",
            ok=True,
            message=(
                f"Branch '{gate.protected_branch}' on {gate.check_repo} requires "
                f"status check '{gate.status_context}'."
            ),
        )
    if configured is False:
        return CheckResult(
            name="gate_branch_protection",
            ok=True,
            message=(
                f"WARNING: Branch '{gate.protected_branch}' on {gate.check_repo} does NOT require "
                f"status check '{gate.status_context}'. Configure Forgejo branch protection — "
                "see docs/gate-enforcement.md."
            ),
        )
    return CheckResult(
        name="gate_branch_protection",
        ok=False,
        message=(
            f"Could not determine branch protection for {gate.check_repo} — "
            "verify manually (see docs/gate-enforcement.md)."
        ),
    )


def run_startup_checks(config: AppConfig) -> list[CheckResult]:
    results = [
        check_findings_store_path(config),
        check_git_token(config),
        check_git_sovereignty(config),
        check_no_telemetry_config(config),
        check_policy_config(config),
        check_gate_branch_protection(config),
        *check_required_assets(config),
    ]
    if config.sovereignty.deny_egress:
        results.append(check_egress_blocked(config))
    return results


def assert_startup_ok(config: AppConfig) -> None:
    results = run_startup_checks(config)
    failures = [result for result in results if not result.ok]
    if failures:
        lines = "\n".join(f"  - [{item.name}] {item.message}" for item in failures)
        raise RuntimeError(f"Shift-Left startup self-check failed:\n{lines}")
