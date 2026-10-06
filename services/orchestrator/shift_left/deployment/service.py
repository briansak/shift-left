"""Plan-only deployment service — gate enforced server-side."""

from __future__ import annotations

import os
from pathlib import Path

from shift_left.approval.service import ApprovalService
from shift_left.config import AppConfig, ManagedTargetConfig
from shift_left.deployment.terraform_plan import (
    PlanRunResult,
    collect_secret_values,
    run_terraform_plan,
    sanitize_secrets,
)
from shift_left.models.database import AuditStore, PlanStore
from shift_left.models.schema import TerraformPlanRecord


class DeploymentPlanService:
    def __init__(
        self,
        *,
        config: AppConfig,
        plans: PlanStore,
        approvals: ApprovalService,
        audit: AuditStore,
        plan_runner=run_terraform_plan,
    ) -> None:
        self._config = config
        self._plans = plans
        self._approvals = approvals
        self._audit = audit
        self._plan_runner = plan_runner

    def _fmc_cfg(self):
        return self._config.deployment.fmc

    def _resolve_workdir(self) -> Path:
        raw = self._fmc_cfg().terraform_workdir
        path = Path(raw)
        if not path.is_absolute():
            from shift_left.config import resolve_config_path

            repo_root = resolve_config_path().parent.parent
            path = repo_root / raw
        return path

    def _plan_env(self) -> dict[str, str]:
        cfg = self._fmc_cfg()
        # Pass through only variable names — values stay in process env, never logged.
        mapping = {
            cfg.username_env: os.environ.get(cfg.username_env, ""),
            cfg.password_env: os.environ.get(cfg.password_env, ""),
            cfg.host_env: os.environ.get(cfg.host_env, ""),
        }
        return {key: value for key, value in mapping.items() if key and value}

    def _secret_values(self) -> list[str]:
        cfg = self._fmc_cfg()
        return collect_secret_values(cfg.username_env, cfg.password_env, cfg.host_env)

    def _missing_credential_envs(self) -> list[str]:
        cfg = self._fmc_cfg()
        return [
            name
            for name in (cfg.username_env, cfg.password_env, cfg.host_env)
            if name and not os.environ.get(name)
        ]

    def target_plan_status(self, target: ManagedTargetConfig) -> tuple[bool, str | None]:
        """Whether Generate plan is available for this target, and why not."""
        if target.deployment_adapter == "none":
            return False, "This target's deployment adapter is none — plan generation is disabled."
        if target.deployment_adapter != "fmc":
            return (
                False,
                "Plan generation uses the FMC Terraform adapter. Set this target's "
                "deployment_adapter to fmc and enable deployment.fmc.enabled in config/shift-left.yaml.",
            )
        if not self._fmc_cfg().enabled:
            return (
                False,
                "FMC plan deployment is disabled in configuration. Set deployment.fmc.enabled: true "
                "in config/shift-left.yaml and restart the orchestrator.",
            )
        missing = self._missing_credential_envs()
        if missing:
            return (
                False,
                "FMC credentials are not configured in the orchestrator environment "
                f"(missing: {', '.join(missing)}).",
            )
        workdir = self._resolve_workdir()
        if not workdir.is_dir():
            return False, f"Terraform workdir not found: {workdir}"
        return True, None

    async def generate_plan(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        actor: str,
    ) -> TerraformPlanRecord:
        if not self._fmc_cfg().enabled:
            raise ValueError("FMC plan deployment is disabled in configuration.")

        gate = self._approvals.check_deployment_gate(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
        )
        if not gate.allowed:
            raise PermissionError(
                f"Deployment gate does not allow planning for {commit_sha}: {gate.reason}"
            )

        git = self._approvals._git
        if git is not None:
            from shift_left.git.head_sha import assert_head_sha_unchanged, pr_number_from_ref

            await assert_head_sha_unchanged(
                git,
                repo=repo,
                pr_number=pr_number_from_ref(pr_ref),
                rendered_sha=commit_sha,
            )

        secrets = self._secret_values()
        missing = self._missing_credential_envs()
        if missing:
            raise ValueError(
                "FMC credentials not configured in environment "
                f"(missing: {', '.join(missing)})."
            )

        workdir = self._resolve_workdir()
        result: PlanRunResult = await self._plan_runner(
            workdir=workdir,
            terraform_bin=self._fmc_cfg().terraform_bin,
            extra_env=self._plan_env(),
        )

        safe_output = sanitize_secrets(result.output_text, secrets)
        record = TerraformPlanRecord(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            target=self._fmc_cfg().target_label,
            summary_add=result.summary_add,
            summary_change=result.summary_change,
            summary_destroy=result.summary_destroy,
            output_text=safe_output,
            generated_by=actor,
            duration_ms=result.duration_ms,
        )
        self._plans.save(record)

        self._audit.log(
            actor=actor,
            action="deployment.plan_generated",
            subject=f"{repo}/{pr_ref}",
            details={
                "commit_sha": commit_sha,
                "target": record.target,
                "summary_add": record.summary_add,
                "summary_change": record.summary_change,
                "summary_destroy": record.summary_destroy,
                "duration_ms": record.duration_ms,
                "exit_code": result.exit_code,
            },
        )
        return record

    async def generate_target_plan(
        self,
        *,
        target_id: str,
        commit_sha: str,
        actor: str,
    ) -> TerraformPlanRecord:
        from shift_left.targets.registry import ManagedTargetRegistry

        registry = ManagedTargetRegistry(self._config)
        target = registry.get(target_id)
        if target is None:
            raise ValueError(f"Unknown managed target: {target_id}")

        allowed, reason = self.target_plan_status(target)
        if not allowed:
            raise ValueError(reason or "Plan generation is not available for this target.")

        git = self._approvals._git
        if git is None:
            raise ValueError("Git backend unavailable")
        owner, repo_name = target.repo.split("/", 1)
        get_branch = getattr(git, "get_branch", None)
        if get_branch is None:
            raise ValueError("Git backend cannot read branch head")
        branch = await get_branch(owner, repo_name, target.branch)
        live_sha = (branch.get("commit") or {}).get("id") or ""
        if live_sha != commit_sha:
            raise ValueError(
                f"Stale SHA — declared branch head is now {live_sha[:7]}, not {commit_sha[:7]}."
            )

        list_statuses = getattr(git, "list_commit_statuses", None)
        if list_statuses is None:
            raise PermissionError("Cannot verify gate status for declared head")
        statuses = await list_statuses(owner, repo_name, commit_sha)
        context = self._config.gate.status_context
        gate_ok = any(
            item.get("context") == context and str(item.get("status", "")).lower() == "success"
            for item in statuses
        )
        if not gate_ok:
            raise PermissionError(
                f"Deployment gate does not allow planning for {commit_sha}: "
                f"no allowing '{context}' status on live head."
            )

        secrets = self._secret_values()
        missing = self._missing_credential_envs()
        if missing:
            raise ValueError(
                "FMC credentials not configured in environment "
                f"(missing: {', '.join(missing)})."
            )

        workdir = self._resolve_workdir()
        result: PlanRunResult = await self._plan_runner(
            workdir=workdir,
            terraform_bin=self._fmc_cfg().terraform_bin,
            extra_env=self._plan_env(),
        )

        safe_output = sanitize_secrets(result.output_text, secrets)
        record = TerraformPlanRecord(
            repo=target.repo,
            pr_ref=f"TARGET-{target_id}",
            commit_sha=commit_sha,
            target=target_id,
            summary_add=result.summary_add,
            summary_change=result.summary_change,
            summary_destroy=result.summary_destroy,
            output_text=safe_output,
            generated_by=actor,
            duration_ms=result.duration_ms,
        )
        self._plans.save(record)
        self._audit.log(
            actor=actor,
            action="deployment.target_plan_generated",
            subject=f"target/{target_id}",
            details={
                "commit_sha": commit_sha,
                "target_id": target_id,
                "summary_destroy": result.summary_destroy,
            },
        )
        return record

    def plan_for_commit(self, repo: str, pr_ref: str, commit_sha: str) -> TerraformPlanRecord | None:
        return self._plans.for_commit(repo, pr_ref, commit_sha)

    def latest_plan(self, repo: str, pr_ref: str) -> TerraformPlanRecord | None:
        return self._plans.latest_for_pr(repo, pr_ref)

    def invalidate_plans(self, repo: str, pr_ref: str, *, new_commit_sha: str) -> int:
        return self._plans.invalidate_for_new_commit(
            repo, pr_ref, new_commit_sha=new_commit_sha
        )
