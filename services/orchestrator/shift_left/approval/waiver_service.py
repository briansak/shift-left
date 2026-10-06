"""Grant and invalidate per-finding waivers."""

from __future__ import annotations

from shift_left.auth.context import TokenCapability
from shift_left.config import AppConfig
from shift_left.git.protocol import GitBackend
from shift_left.models.database import AuditStore, FindingWaiverStore, FindingsStore, PolicyDecisionStore
from shift_left.models.schema import FindingWaiverRecord
from shift_left.policy.finding_waiver import finding_waiver_identity
from shift_left.policy.waiver_policy import (
    assert_finding_waivable,
    assert_sufficient_waiver_capability,
    required_waiver_capability,
)


def _normalize_identity(value: str) -> str:
    return value.strip().lower()


def _split_repo_slug(repo: str) -> tuple[str, str]:
    owner, _, name = repo.partition("/")
    if not name:
        raise ValueError(f"Invalid repo slug: {repo!r}")
    return owner, name


class FindingWaiverService:
    def __init__(
        self,
        *,
        config: AppConfig,
        findings_store: FindingsStore,
        policy_decisions: PolicyDecisionStore,
        waivers: FindingWaiverStore,
        audit: AuditStore,
        git: GitBackend | None = None,
    ) -> None:
        self._config = config
        self._findings = findings_store
        self._policy_decisions = policy_decisions
        self._waivers = waivers
        self._audit = audit
        self._git = git

    async def grant_waiver(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        finding_id: str,
        actor: str,
        reason: str,
        capability_used: TokenCapability,
    ) -> FindingWaiverRecord:
        if not reason.strip():
            raise ValueError("Waiver requires a non-empty reason.")

        finding = self._findings.get(finding_id)
        if finding is None:
            raise ValueError(f"Finding {finding_id} not found.")
        if finding.repo != repo or finding.pr_ref != pr_ref:
            raise ValueError("Finding does not belong to this pull request.")
        if finding.commit_sha != commit_sha:
            raise ValueError(
                f"Finding is bound to commit {finding.commit_sha}, not {commit_sha}."
            )

        assert_finding_waivable(finding, self._config)

        policy_decision = self._policy_decisions.for_commit(repo, pr_ref, commit_sha)
        required = required_waiver_capability(
            finding,
            policy_decision.finding_decisions if policy_decision else None,
        )
        assert_sufficient_waiver_capability(
            capability_used=capability_used,
            required=required,
        )

        identity = finding_waiver_identity(finding)
        if identity is None:
            raise ValueError(
                "Finding has no registry waiver identity (rule_id missing); cannot waive."
            )

        if self._git is not None:
            from shift_left.git.head_sha import assert_head_sha_unchanged, pr_number_from_ref

            await assert_head_sha_unchanged(
                self._git,
                repo=repo,
                pr_number=pr_number_from_ref(pr_ref),
                rendered_sha=commit_sha,
            )

        commit_author: str | None = None
        actor_matches_author: bool | None = None
        if self._git is not None:
            owner, repo_name = _split_repo_slug(repo)
            commit_author = await self._git.get_commit_author(owner, repo_name, commit_sha)

        if commit_author and actor:
            actor_matches_author = _normalize_identity(actor) == _normalize_identity(commit_author)

        if actor_matches_author and not self._config.rbac.allow_self_approval:
            raise ValueError(
                "Separation of duties: waiver cannot be self-granted "
                f"(author={commit_author!r}, actor={actor!r})."
            )

        self_granted = bool(actor_matches_author and self._config.rbac.allow_self_approval)

        record = FindingWaiverRecord(
            repo=repo,
            pr_ref=pr_ref,
            commit_sha=commit_sha,
            target_kind=identity.target_kind,
            rule_id=identity.rule_id,
            file_path=identity.file_path,
            line_start=identity.line_start,
            construct_key=identity.construct_key,
            weakness_class=identity.weakness_class,
            finding_id=finding.id,
            actor=actor,
            reason=reason.strip(),
            commit_author=commit_author,
            actor_matches_author=actor_matches_author,
            self_granted=self_granted,
            granted_with_capability=capability_used.value,
        )
        saved = self._waivers.grant(record)
        self._audit.log(
            actor=actor,
            action="waiver.granted",
            subject=f"{repo}/{pr_ref}",
            details={
                "waiver_id": saved.id,
                "commit_sha": commit_sha,
                "target_kind": saved.target_kind,
                "rule_id": saved.rule_id,
                "file_path": saved.file_path,
                "line_start": saved.line_start,
                "construct_key": saved.construct_key,
                "weakness_class": saved.weakness_class,
                "finding_id": saved.finding_id,
                "reason": saved.reason,
                "self_granted": saved.self_granted,
                "actor_matches_author": saved.actor_matches_author,
                "granted_with_capability": saved.granted_with_capability,
                "required_capability": required.value,
            },
        )
        return saved

    def invalidate_on_new_commit(
        self,
        repo: str,
        pr_ref: str,
        *,
        new_commit_sha: str,
        actor: str,
    ) -> list[FindingWaiverRecord]:
        expired = self._waivers.invalidate_for_new_commit(
            repo,
            pr_ref,
            new_commit_sha=new_commit_sha,
            reason=f"New commit {new_commit_sha} landed — waiver bound to prior SHA expired.",
        )
        for record in expired:
            self._audit.log(
                actor=actor,
                action="waiver.expired",
                subject=f"{repo}/{pr_ref}",
                details={
                    "waiver_id": record.id,
                    "prior_commit_sha": record.commit_sha,
                    "new_commit_sha": new_commit_sha,
                    "target_kind": record.target_kind,
                    "rule_id": record.rule_id,
                    "file_path": record.file_path,
                    "line_start": record.line_start,
                    "construct_key": record.construct_key,
                    "weakness_class": record.weakness_class,
                    "finding_id": record.finding_id,
                    "reason": record.reason,
                },
            )
        return expired

    def active_for_commit(self, repo: str, pr_ref: str, commit_sha: str) -> list[FindingWaiverRecord]:
        return self._waivers.active_for_commit(repo, pr_ref, commit_sha)

    def log_waiver_use(
        self,
        *,
        repo: str,
        pr_ref: str,
        commit_sha: str,
        actor: str,
        waivers_used: tuple[FindingWaiverRecord, ...],
    ) -> None:
        for waiver in waivers_used:
            self._audit.log(
                actor=actor,
                action="waiver.used",
                subject=f"{repo}/{pr_ref}",
                details={
                    "waiver_id": waiver.id,
                    "commit_sha": commit_sha,
                    "target_kind": waiver.target_kind,
                    "rule_id": waiver.rule_id,
                    "file_path": waiver.file_path,
                    "line_start": waiver.line_start,
                    "construct_key": waiver.construct_key,
                    "weakness_class": waiver.weakness_class,
                    "finding_id": waiver.finding_id,
                    "reason": waiver.reason,
                    "self_granted": waiver.self_granted,
                    "granted_with_capability": waiver.granted_with_capability,
                },
            )
