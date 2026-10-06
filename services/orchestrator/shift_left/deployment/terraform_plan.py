"""Terraform plan execution — FMC provider, plan-only."""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PlanRunResult:
    output_text: str
    summary_add: int
    summary_change: int
    summary_destroy: int
    duration_ms: int
    exit_code: int


_PLAN_SUMMARY = re.compile(
    r"Plan:\s+(\d+)\s+to add,\s+(\d+)\s+to change,\s+(\d+)\s+to destroy",
    re.IGNORECASE,
)


def collect_secret_values(*env_names: str) -> list[str]:
    values: list[str] = []
    for name in env_names:
        if not name:
            continue
        value = os.environ.get(name, "")
        if value:
            values.append(value)
    return values


def sanitize_secrets(text: str, secrets: list[str]) -> str:
    result = text
    for secret in secrets:
        if len(secret) < 4:
            continue
        result = result.replace(secret, "[REDACTED]")
    return result


def parse_plan_summary(output: str) -> tuple[int, int, int]:
    match = _PLAN_SUMMARY.search(output)
    if not match:
        return 0, 0, 0
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


async def run_terraform_plan(
    *,
    workdir: Path,
    terraform_bin: str,
    extra_env: dict[str, str],
    timeout_seconds: float = 600.0,
) -> PlanRunResult:
    """
    Execute `terraform plan` locally — no apply, no write beyond plan cache.

    TODO: verify `terraform init` provider lock and CiscoDevNet/fmc version against lab FMC.
    TODO: confirm `-lock=false` and backend settings for your FMC Terraform layout.
    """
    if not workdir.is_dir():
        raise FileNotFoundError(f"Terraform workdir not found: {workdir}")

    env = os.environ.copy()
    env.update(extra_env)

    start = time.perf_counter()

    async def _run(args: list[str]) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            terraform_bin,
            *args,
            cwd=str(workdir),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError("terraform plan timed out") from None
        out = stdout.decode(errors="replace")
        err = stderr.decode(errors="replace")
        return proc.returncode or 0, out, err

    init_code, init_out, init_err = await _run(["init", "-input=false", "-no-color"])
    combined_init = f"{init_out}\n{init_err}".strip()
    if init_code != 0:
        duration_ms = int((time.perf_counter() - start) * 1000)
        return PlanRunResult(
            output_text=combined_init or "terraform init failed",
            summary_add=0,
            summary_change=0,
            summary_destroy=0,
            duration_ms=duration_ms,
            exit_code=init_code,
        )

    plan_code, plan_out, plan_err = await _run(
        ["plan", "-input=false", "-no-color", "-detailed-exitcode"]
    )
    combined = f"{plan_out}\n{plan_err}".strip()
    add, change, destroy = parse_plan_summary(combined)
    duration_ms = int((time.perf_counter() - start) * 1000)
    return PlanRunResult(
        output_text=combined or "terraform plan produced no output",
        summary_add=add,
        summary_change=change,
        summary_destroy=destroy,
        duration_ms=duration_ms,
        exit_code=plan_code,
    )
