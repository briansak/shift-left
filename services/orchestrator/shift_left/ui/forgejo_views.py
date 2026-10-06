"""Presentation helpers for embedded Forgejo PR views."""

from __future__ import annotations

from typing import Any

from shift_left.models.schema import ApprovalRecord, DeploymentGateResult


def build_commit_timeline(
    commits: list[dict[str, Any]],
    approvals: list[ApprovalRecord],
    *,
    head_sha: str,
) -> list[dict[str, Any]]:
    """Annotate PR commits with approval binding and post-approval invalidation."""
    sha_order = [item.get("sha") or "" for item in commits]
    sha_index = {sha: index for index, sha in enumerate(sha_order) if sha}

    active_bound = {
        record.commit_sha
        for record in approvals
        if not record.invalidated
    }
    invalidated = [record for record in approvals if record.invalidated]

    rows: list[dict[str, Any]] = []
    for commit in commits:
        sha = commit.get("sha") or ""
        commit_data = commit.get("commit") or {}
        author = commit_data.get("author") or {}
        message = (commit_data.get("message") or "").splitlines()[0]
        row = {
            "sha": sha,
            "sha_short": sha[:7] if sha else "",
            "message": message,
            "author": author.get("name") or author.get("email") or "unknown",
            "created_at": commit_data.get("date"),
            "is_head": sha == head_sha,
            "approval_bound": sha in active_bound,
            "was_approved_here": any(record.commit_sha == sha for record in approvals),
            "landed_after_approval": False,
            "invalidates_approval": False,
            "invalidation_reason": None,
        }
        for record in invalidated:
            approved_idx = sha_index.get(record.commit_sha)
            current_idx = sha_index.get(sha)
            if approved_idx is None or current_idx is None:
                continue
            if current_idx > approved_idx:
                row["landed_after_approval"] = True
                if current_idx == approved_idx + 1 or sha == head_sha:
                    row["invalidates_approval"] = True
                    row["invalidation_reason"] = record.invalidation_reason
        rows.append(row)
    return rows


def compare_gate_status(
    *,
    gate: DeploymentGateResult,
    forgejo_statuses: list[dict[str, Any]],
) -> dict[str, Any]:
    context = gate.commit_status_context
    orchestrator_state = "success" if gate.allowed else "failure"
    forgejo_match = next(
        (item for item in forgejo_statuses if item.get("context") == context),
        None,
    )
    if forgejo_match is None:
        return {
            "context": context,
            "orchestrator_state": orchestrator_state,
            "orchestrator_allowed": gate.allowed,
            "forgejo_state": None,
            "forgejo_description": None,
            "matches": None,
            "discrepancy": "Forgejo has no commit status for the configured gate context yet.",
        }
    forgejo_state = str(forgejo_match.get("status") or forgejo_match.get("state") or "").lower()
    expected = orchestrator_state
    matches = forgejo_state == expected
    discrepancy = None
    if not matches:
        discrepancy = (
            f"Forgejo reports {forgejo_state!r} for context {context!r} while the orchestrator "
            f"gate {'allows' if gate.allowed else 'blocks'} this commit ({orchestrator_state!r})."
        )
    return {
        "context": context,
        "orchestrator_state": orchestrator_state,
        "orchestrator_allowed": gate.allowed,
        "forgejo_state": forgejo_state,
        "forgejo_description": forgejo_match.get("description"),
        "matches": matches,
        "discrepancy": discrepancy,
    }
