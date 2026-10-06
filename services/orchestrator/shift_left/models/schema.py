"""Shared data models: Finding, Policy, AuditEvent.

Gate severity for uninterpretable content
---------------------------------------
**Decision: both block.** Findings that represent content the gate cannot
interpret use handler CWEs that map to ``policy_severity=high`` and match
default BLOCK policies:

- **CWE-657** — changed file outside ``routing.code_globs`` /
  ``routing.config_globs`` (unclaimed path). No handler runs on the file.
- **CWE-754** — access-list line or object reference inside a *claimed* config
  file that the structural parser cannot represent (ASA-007).

Both fail closed: merge is blocked until the path is claimed, the ACL is
rewritten into a supported form, or an operator documents an explicit gate
exclusion. See ``docs/gate-enforcement.md`` § Uninterpretable content.

**Routing precedence:** when a path matches both ``code_globs`` and parser-scoped
``config_globs`` (``config_globs`` ∧ ``deterministic_parser_globs``), the
deterministic config gate is authoritative; the file is not treated as code-only
for gate purposes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class FindingSource(str, Enum):
    ANTARES = "antares"
    CODE_HANDLER = "code-handler"
    FOUNDATION_SEC = "foundation-sec"
    HANDLER = "handler"


class TargetKind(str, Enum):
    CODE = "code"
    CONFIG = "config"


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicySeverity(str, Enum):
    """Deterministic severity used exclusively for policy evaluation."""

    UNCLASSIFIED = "unclassified"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyAction(str, Enum):
    PASS = "pass"
    FLAG = "flag"
    BLOCK = "block"


class LineRange(BaseModel):
    start: int
    end: int


class EnrichmentStatus(str, Enum):
    """Whether reference-data enrichment was applied to a finding."""

    NONE = "none"
    ENRICHED = "enriched"
    CACHE_EMPTY = "cache_empty"
    CACHE_STALE = "cache_stale"
    PARTIAL = "partial"


class FindingEnrichment(BaseModel):
    """
    Reference-data attachment — distinct from model-asserted fields on Finding.

    Populated from the local CVE/CWE cache only; never from network at runtime.
    """

    status: EnrichmentStatus = EnrichmentStatus.NONE
    cwe_detail: str | None = None
    cve_summaries: list[str] = Field(default_factory=list)
    reference_data_version: str | None = None
    reference_synced_at: datetime | None = None
    stale: bool = False
    note: str | None = None


class Finding(BaseModel):
    """Normalized security finding from any model source.

    ``handler_asserted_cwe`` drives ``policy_severity`` (see
    ``shift_left.policy.severity``). CWE-657 (unclaimed file) and CWE-754
    (uninterpretable ACL / ASA-007) both map to HIGH and block the gate by
    default — see module docstring.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    source: FindingSource
    target_kind: TargetKind
    repo: str
    pr_ref: str
    commit_sha: str
    file_path: str
    line_range: LineRange | None = None
    model_asserted_cwe: str | None = None
    model_cwe_recognized: bool | None = None
    handler_asserted_cwe: str | None = None
    cve_refs: list[str] = Field(default_factory=list)
    model_asserted_severity: Severity = Severity.MEDIUM
    policy_severity: PolicySeverity = PolicySeverity.UNCLASSIFIED
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    title: str
    description: str
    evidence: str | None = None
    trace: str | None = None
    enrichment: FindingEnrichment | None = None
    model_context: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    enrichment_source: str | None = None
    enrichment_generated_at: datetime | None = None
    construct_key: str | None = None
    status: FindingStatus = FindingStatus.OPEN
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @property
    def severity(self) -> Severity:
        """Backward-compatible alias for model-asserted severity (not used by policy)."""
        return self.model_asserted_severity

    @property
    def cwe(self) -> str | None:
        """Backward-compatible alias for model-asserted CWE (not used by policy)."""
        return self.model_asserted_cwe

    @property
    def is_model_only(self) -> bool:
        """True when the model asserted a CWE but no deterministic handler rule matched."""
        return bool(self.model_asserted_cwe) and not self.handler_asserted_cwe

    @model_validator(mode="before")
    @classmethod
    def _coerce_legacy_fields(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "severity" in data and "model_asserted_severity" not in data:
            data["model_asserted_severity"] = data.pop("severity")
        if "cwe" in data and "model_asserted_cwe" not in data:
            data["model_asserted_cwe"] = data.pop("cwe")
        return data


class OperatorEscalation(BaseModel):
    """Explicit operator override to escalate a registry rule above its default gate action."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    action: PolicyAction = PolicyAction.BLOCK


class PolicyAppliesTo(BaseModel):
    target_kind: TargetKind | None = None
    path_globs: list[str] = Field(default_factory=lambda: ["**/*"])


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    severity_threshold: PolicySeverity | None = None
    cwe_allowlist: list[str] = Field(default_factory=list)
    cwe_blocklist: list[str] = Field(default_factory=list)

    @field_validator("severity_threshold")
    @classmethod
    def _reject_unclassified_threshold(cls, value: PolicySeverity | None) -> PolicySeverity | None:
        if value == PolicySeverity.UNCLASSIFIED:
            raise ValueError("severity_threshold cannot be 'unclassified'")
        return value


class Policy(BaseModel):
    id: str
    name: str
    applies_to: PolicyAppliesTo = Field(default_factory=PolicyAppliesTo)
    rules: list[PolicyRule] = Field(default_factory=lambda: [PolicyRule()])
    action: PolicyAction = PolicyAction.FLAG
    enabled: bool = True

    @field_validator("rules", mode="before")
    @classmethod
    def _coerce_rules(cls, value: object) -> object:
        if isinstance(value, dict):
            return [value]
        return value


class FindingPolicyDecision(BaseModel):
    """Per-finding policy decision with explainability — not a compliance verdict."""

    finding_id: str
    decision: PolicyAction
    matched_policy_id: str | None = None
    matched_policy_name: str | None = None
    matched_rule_index: int | None = None
    rule_explanation: str | None = None
    explanation: str


class PullRequestPolicyDecision(BaseModel):
    """Aggregated PR-level policy decision — advisory gate signal only."""

    repo: str
    pr_ref: str
    commit_sha: str
    default_action: PolicyAction
    pr_decision: PolicyAction
    finding_decisions: list[FindingPolicyDecision] = Field(default_factory=list)
    explanation: str


class ApprovalRecord(BaseModel):
    """Human approval bound to a specific commit SHA."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    pr_ref: str
    commit_sha: str
    approver: str
    commit_author: str | None = None
    approver_matches_author: bool | None = None
    separation_of_duties_result: str | None = None
    approved_at: datetime = Field(default_factory=utc_now)
    findings_snapshot: list[dict[str, Any]] = Field(default_factory=list)
    policy_decision: PolicyAction
    policy_decision_snapshot: dict[str, Any] = Field(default_factory=dict)
    invalidated: bool = False
    invalidated_at: datetime | None = None
    invalidation_reason: str | None = None


class BlockOverrideRecord(BaseModel):
    """Explicit override of a block policy decision — requires separate capability."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    pr_ref: str
    commit_sha: str
    actor: str
    justification: str
    granted_at: datetime = Field(default_factory=utc_now)
    policy_id: str | None = None


class FindingWaiverRecord(BaseModel):
    """Per-finding waiver bound to a specific commit SHA and construct identity.

    Matching uses path + construct_key + weakness class (Constitution VIII).
    ``line_start`` and ``rule_id`` are retained for display and audit.
    Commit SHA is the freshness control: a new SHA invalidates prior waivers.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    pr_ref: str
    commit_sha: str
    target_kind: str
    rule_id: str
    file_path: str
    line_start: int
    construct_key: str
    weakness_class: str
    finding_id: str
    actor: str
    reason: str
    granted_at: datetime = Field(default_factory=utc_now)
    commit_author: str | None = None
    actor_matches_author: bool | None = None
    self_granted: bool = False
    granted_with_capability: str
    invalidated: bool = False
    invalidated_at: datetime | None = None
    invalidation_reason: str | None = None


class GateBlockReason(str, Enum):
    POLICY_BLOCK = "policy_block"
    ANALYSIS_INCOMPLETE = "analysis_incomplete"
    APPROVAL_REQUIRED = "approval_required"
    NO_POLICY_DECISION = "no_policy_decision"


class DeploymentGateResult(BaseModel):
    """Structural deployment gate — approval required; block not silently bypassed."""

    allowed: bool
    reason: str
    commit_sha: str
    policy_decision: PolicyAction
    approval_present: bool
    approval_valid_for_commit: bool
    block_override_present: bool
    block_reason: GateBlockReason | None = None
    analysis_incomplete: bool = False
    separation_of_duties_enforced: bool = True
    separation_of_duties_disabled: bool = False
    rbac_allow_self_approval: bool = False
    commit_status_context: str = "shift-left/gate"
    branch_protection_gate_check_required: bool = True
    branch_protection_gate_check_configured: bool | None = None


class ReviewSummary(BaseModel):
    """Advisory reviewer prose — excluded from determinism checks."""

    summary_text: str
    suggested_course_of_action: str
    findings_covered: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    generator: str
    is_advisory: Literal[True] = True


class CodeLocalization(BaseModel):
    """Deprecated alias — use LocalizationResult for Antares triage output."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    pr_ref: str
    commit_sha: str
    task_cwe: str
    outcome: str
    ranked_files: list[str] = Field(default_factory=list)
    exploration_trace: str | None = None
    terminal_calls_used: int = 0
    terminal_budget: int = 0
    loop_control_enabled: bool = True
    adapter_identity: dict[str, str] = Field(default_factory=dict)
    generation_params: dict[str, Any] = Field(default_factory=dict)
    failure_class: str | None = None
    failure_message: str | None = None
    advisory_only: Literal[True] = True
    created_at: datetime = Field(default_factory=utc_now)


class RankedFileCandidate(BaseModel):
    path: str
    rank: int = Field(ge=1)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class LocalizationResult(BaseModel):
    """Advisory Antares triage output — ranked candidate files, never a Finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    ref: str
    cwe_queried: str
    ranked_files: list[RankedFileCandidate] = Field(default_factory=list)
    exploration_trace: str
    turn_count: int = Field(ge=0, default=0)
    terminal_budget: int = Field(ge=0, default=0)
    loop_control_enabled: bool = True
    adapter_identity: dict[str, str] = Field(default_factory=dict)
    generation_params: dict[str, Any] = Field(default_factory=dict)
    model_variant: str
    model_version: str | None = None
    published_file_f1: float | None = Field(
        default=None,
        description="Published File F1 for the staged model variant (GRPO, from model card).",
    )
    generated_at: datetime = Field(default_factory=utc_now)
    is_advisory: Literal[True] = True
    outcome: str
    summary_text: str


class FindingStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: FindingStatus
    rationale: str | None = None


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str
    action: str
    subject: str
    details: dict[str, Any] = Field(default_factory=dict)


class ReviewRequest(BaseModel):
    owner: str = Field(examples=["example-org"])
    repo: str = Field(examples=["example-configs"])
    pr_number: int = Field(examples=[42])
    commit_sha: str | None = Field(
        default=None,
        examples=["0000000000000000000000000000000000000000"],
    )
    base_ref: str | None = None
    head_ref: str | None = None
    skip_advisory: bool = False


class ChangeState(str, Enum):
    """Server-computed workflow state for a config change (PR)."""

    DRAFT_OPEN = "draft/open"
    VALIDATING = "validating"
    VALIDATION_INCOMPLETE = "validation_incomplete"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    PLAN_GENERATED = "plan_generated"
    PLAN_STALE = "plan_stale"
    DEPLOYED = "deployed"


class ChangeStateResult(BaseModel):
    state: ChangeState
    reason: str
    next_action: str
    commit_sha: str
    repo: str
    pr_ref: str
    pr_number: int | None = None
    gate_allowed: bool = False
    rbac_allow_self_approval: bool = False


class AppliedRevision(BaseModel):
    """Recorded when Phase 5 apply lands — never inferred from merge history."""

    target_id: str
    applied_sha: str
    applied_at: datetime
    actor: str
    plan_reference: str | None = None
    adapter: str
    outcome: Literal["success", "failed"] = "success"


class ConfigChangeSummary(BaseModel):
    repo: str
    pr_ref: str
    pr_number: int
    owner: str
    repo_name: str
    title: str | None = None
    author: str | None = None
    branch: str | None = None
    target_environment: str | None = None
    commit_sha: str
    change_state: ChangeState
    next_action: str
    viewer_action: str | None = None
    config_scope: str = "config"
    gate_allowed: bool | None = None
    forgejo_pr_url: str | None = None
    forgejo_state: str | None = None
    runner_notice: str | None = None
    last_fetched_at: datetime | None = None


class TerraformPlanRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    pr_ref: str
    commit_sha: str
    target: str
    summary_add: int = 0
    summary_change: int = 0
    summary_destroy: int = 0
    output_text: str
    generated_at: datetime = Field(default_factory=utc_now)
    generated_by: str
    duration_ms: int = 0
    stale: bool = False


class ReviewResult(BaseModel):
    repo: str
    pr_ref: str
    commit_sha: str
    findings: list[Finding]
    policy_decision: PullRequestPolicyDecision
    advisory_action: PolicyAction
    message: str
    review_summary: ReviewSummary | None = None
    enrichment_unavailable: bool = False
    code_localizations: list[CodeLocalization] = Field(default_factory=list)
    localization_results: list[LocalizationResult] = Field(default_factory=list)
    analysis_results: list[Any] = Field(default_factory=list)
    stage_timings_ms: dict[str, int] = Field(default_factory=dict)

    @property
    def pr_policy_decision(self) -> PolicyAction:
        """Alias — policy decision, not a compliance verdict."""
        return self.policy_decision.pr_decision
