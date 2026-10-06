"""OpenAPI response models and synthetic examples for the orchestrator HTTP API.

Examples use obviously fake owner/repo/token/SHA values. Do not copy fixture
or validation-corpus paths into this module.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from shift_left.models.schema import (
    ApprovalRecord,
    BlockOverrideRecord,
    ChangeStateResult,
    DeploymentGateResult,
    Finding,
    FindingWaiverRecord,
    PullRequestPolicyDecision,
    ReviewResult,
    TerraformPlanRecord,
)

SYNTHETIC_OWNER = "example-org"
SYNTHETIC_REPO = "example-configs"
SYNTHETIC_REPO_SLUG = f"{SYNTHETIC_OWNER}/{SYNTHETIC_REPO}"
SYNTHETIC_PR = 42
SYNTHETIC_PR_REF = f"PR-{SYNTHETIC_PR}"
SYNTHETIC_SHA = "0000000000000000000000000000000000000000"
SYNTHETIC_TOKEN = "slt_EXAMPLE"
SYNTHETIC_FILE = "terraform/policies/edge.tf"
SYNTHETIC_FINDING_ID = "00000000-0000-4000-8000-000000000001"


class OpenApiLooseModel(BaseModel):
    """Declared JSON object that may grow extra keys without failing serialization."""

    model_config = ConfigDict(extra="allow")


class HealthResponse(OpenApiLooseModel):
    status: str
    ready: bool | None = None


class SelfCheckItem(BaseModel):
    name: str
    ok: bool
    message: str


class SelfCheckResponse(BaseModel):
    ok: bool
    checks: list[SelfCheckItem]


class InvestigationLaunchResponse(OpenApiLooseModel):
    investigation_id: str
    state: str
    resolved_commit_sha: str | None = None
    snapshot_bytes: int | None = None
    snapshot_warn: str | None = None
    cwe_hint: str | None = None


class InvestigationBatchLaunchResponse(OpenApiLooseModel):
    batch_id: str
    source: str
    investigation_ids: list[str]
    investigation_count: int
    estimated_wall_clock_seconds: float | None = None
    top25_survivor_count: int | None = None
    snapshot_bytes: int | None = None


class InvestigationStateResponse(OpenApiLooseModel):
    investigation_id: str
    state: str
    originating_investigation_id: str | None = None
    resolved_commit_sha: str | None = None


class CandidateDispositionResponse(OpenApiLooseModel):
    investigation_id: str
    submission_rank: int
    file_path: str
    disposition: str
    disposition_actor: str | None = None
    disposition_at: str | None = None
    disposition_note: str | None = None


class AntaresTriageResponse(OpenApiLooseModel):
    """Synchronous advisory localization payload (legacy entry)."""


class FindingsListResponse(OpenApiLooseModel):
    findings: list[Finding] = Field(default_factory=list)
    count: int | None = None


class PolicyDocumentResponse(OpenApiLooseModel):
    policy: dict[str, Any]
    note: str


class PolicyValidateResponse(BaseModel):
    ok: bool
    policy_count: int
    precedence: str


class ApprovalRevokeResponse(BaseModel):
    revoked: int


class ConfigChangeListResponse(OpenApiLooseModel):
    changes: list[dict[str, Any]]
    count: int


class SandboxAuditIngestResponse(BaseModel):
    status: str


class AuditEventListResponse(OpenApiLooseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)


class AuditExportResponse(OpenApiLooseModel):
    exported_at: str
    integrity: dict[str, Any]
    events: list[dict[str, Any]] = Field(default_factory=list)


class TokenIdentityResponse(BaseModel):
    actor: str
    capabilities: list[str]
    token_id: str


class ApprovalListResponse(OpenApiLooseModel):
    approvals: list[ApprovalRecord] = Field(default_factory=list)


class JsonObjectResponse(OpenApiLooseModel):
    """UI-backing JSON whose keys vary by page."""


REVIEW_REQUEST_EXAMPLE: dict[str, Any] = {
    "owner": SYNTHETIC_OWNER,
    "repo": SYNTHETIC_REPO,
    "pr_number": SYNTHETIC_PR,
    "commit_sha": SYNTHETIC_SHA,
    "skip_advisory": False,
}

REVIEW_RESPONSE_EXAMPLE: dict[str, Any] = {
    "repo": SYNTHETIC_REPO_SLUG,
    "pr_ref": SYNTHETIC_PR_REF,
    "commit_sha": SYNTHETIC_SHA,
    "findings": [
        {
            "id": SYNTHETIC_FINDING_ID,
            "source": "handler",
            "target_kind": "config",
            "repo": SYNTHETIC_REPO_SLUG,
            "pr_ref": SYNTHETIC_PR_REF,
            "commit_sha": SYNTHETIC_SHA,
            "file_path": SYNTHETIC_FILE,
            "line_range": {"start": 12, "end": 18},
            "handler_asserted_cwe": "CWE-284",
            "policy_severity": "high",
            "confidence": 1.0,
            "title": "Deterministic rule: TF-001",
            "description": "Internet-wide ingress on an example security-group rule.",
            "evidence": "cidr_blocks = [\"0.0.0.0/0\"]",
            "trace": "handler:TF-001",
            "construct_key": "rule:EXAMPLE-INGRESS:seq:0",
            "status": "open",
            "cve_refs": [],
            "recommended_actions": [],
            "model_asserted_cwe": None,
            "model_cwe_recognized": None,
        }
    ],
    "policy_decision": {
        "repo": SYNTHETIC_REPO_SLUG,
        "pr_ref": SYNTHETIC_PR_REF,
        "commit_sha": SYNTHETIC_SHA,
        "default_action": "block",
        "pr_decision": "block",
        "finding_decisions": [
            {
                "finding_id": SYNTHETIC_FINDING_ID,
                "decision": "block",
                "matched_policy_id": "example-block-high",
                "matched_policy_name": "Block high-severity handler findings",
                "matched_rule_index": 0,
                "rule_explanation": "policy_severity high matches BLOCK.",
                "explanation": "Handler finding TF-001 is BLOCK under the example policy.",
            }
        ],
        "explanation": "One handler finding matched a BLOCK policy.",
    },
    "advisory_action": "flag",
    "message": "1 advisory finding(s) omitted from this response (omit_from_review_api).",
    "review_summary": None,
    "enrichment_unavailable": False,
    "code_localizations": [],
    "localization_results": [],
    "analysis_results": [],
    "stage_timings_ms": {"handlers": 12, "policy": 3},
}

# Re-export schema types used as response_model on routes.
__all__ = [
    "ApprovalListResponse",
    "ApprovalRecord",
    "ApprovalRevokeResponse",
    "AntaresTriageResponse",
    "AuditEventListResponse",
    "AuditExportResponse",
    "BlockOverrideRecord",
    "CandidateDispositionResponse",
    "ChangeStateResult",
    "ConfigChangeListResponse",
    "DeploymentGateResult",
    "Finding",
    "FindingsListResponse",
    "FindingWaiverRecord",
    "HealthResponse",
    "InvestigationBatchLaunchResponse",
    "InvestigationLaunchResponse",
    "InvestigationStateResponse",
    "JsonObjectResponse",
    "PolicyDocumentResponse",
    "PolicyValidateResponse",
    "PullRequestPolicyDecision",
    "REVIEW_REQUEST_EXAMPLE",
    "REVIEW_RESPONSE_EXAMPLE",
    "ReviewResult",
    "SandboxAuditIngestResponse",
    "SelfCheckResponse",
    "SYNTHETIC_FILE",
    "SYNTHETIC_FINDING_ID",
    "SYNTHETIC_OWNER",
    "SYNTHETIC_PR",
    "SYNTHETIC_PR_REF",
    "SYNTHETIC_REPO",
    "SYNTHETIC_REPO_SLUG",
    "SYNTHETIC_SHA",
    "SYNTHETIC_TOKEN",
    "TerraformPlanRecord",
    "TokenIdentityResponse",
]
