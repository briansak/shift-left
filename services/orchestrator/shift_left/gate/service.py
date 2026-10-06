"""Deployment gate evaluation and commit status publishing."""

from __future__ import annotations

from shift_left.approval.service import ApprovalService
from shift_left.config import AppConfig
from shift_left.git.protocol import GitBackend
from shift_left.models.schema import DeploymentGateResult


def _gate_status_state(result: DeploymentGateResult) -> str:
    return "success" if result.allowed else "failure"


class GateService:
    def __init__(
        self,
        *,
        config: AppConfig,
        git: GitBackend,
        approvals: ApprovalService,
    ) -> None:
        self._config = config
        self._git = git
        self._approvals = approvals

    async def evaluate_and_publish(
        self,
        *,
        owner: str,
        repo_name: str,
        repo_slug: str,
        pr_ref: str,
        commit_sha: str,
        pr_number: int | None = None,
        analysis_results: list | None = None,
    ) -> DeploymentGateResult:
        result = self._approvals.check_deployment_gate(
            repo=repo_slug,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            analysis_results=analysis_results,
        )
        gate = self._config.gate
        if gate.enabled and gate.publish_commit_status:
            target_url = None
            if pr_number is not None and hasattr(self._git, "_base_url"):
                base = getattr(self._git, "_base_url", "")
                target_url = f"{base}/{owner}/{repo_name}/pulls/{pr_number}"
            try:
                await self._git.publish_commit_status(
                    owner,
                    repo_name,
                    commit_sha,
                    context=gate.status_context,
                    state=_gate_status_state(result),
                    description=result.reason[:255],
                    target_url=target_url,
                )
            except Exception:
                pass
        return result
