"""YAML configuration loader."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import AliasChoices, BaseModel, Field, model_validator

from shift_left.git.protocol import GitBackendKind
from shift_left.models.schema import (
    OperatorEscalation,
    AppliedRevision,
    Policy,
    PolicyAction,
    PolicyRule,
    PolicyAppliesTo,
    TargetKind,
)
from shift_left.sovereignty.network import AllowedEndpoint

CURRENT_SCHEMA_VERSION = 11

logger = logging.getLogger(__name__)

_LEGACY_CONTAINER_DATA_ROOTS = ("/shift-left/data", "/data")


def _parser_scoped_blocking_path_globs() -> list[str]:
    """Path globs for structural parser outputs — shared by CWE-284/754 block policies."""
    from shift_left.handlers.config.parser_scope import BLOCKING_POLICY_PATH_GLOBS

    return list(BLOCKING_POLICY_PATH_GLOBS)


class SovereigntyConfig(BaseModel):
    # Runtime: analyzed artifacts (code, configs, findings, inference) never egress.
    deny_egress: bool = True
    required_assets: list[dict[str, str]] = Field(default_factory=list)
    # Extra host:port entries (e.g. "my-host:8090") — not whole-host wildcards.
    runtime_allowed_endpoints: list[str] = Field(default_factory=list)


class ReferenceDataConfig(BaseModel):
    # Repo-relative. Compose maps data/* onto SHIFT_LEFT_DATA_DIR (/data).
    cache_dir: str = "data/reference"
    enrich_findings: bool = True
    max_staleness_days: int = 30
    nvd_api_key_env: str = "NVD_API_KEY"


class DistributionConfig(BaseModel):
    """
    Documents install/update vs runtime boundaries.

    Install/update egress (GitHub, Hugging Face, registries) is operator-initiated
    via `shift-left install`, `shift-left update`, or offline bundles — never automatic.
    """

    install_source: str = "github"
    auto_update: bool = False  # enforced false — no background update checks
    telemetry: bool = False  # enforced absent — not opt-out


class GitBundledConfig(BaseModel):
    """Bundled Forgejo/Gitea — hosts customer repos on the local host (sovereign default)."""

    provider: str = "forgejo"
    url: str = "http://forgejo:3000"
    token_env: str = "FORGEJO_TOKEN"
    default_owner: str = "shift-left"


class GitHubBackendConfig(BaseModel):
    api_url: str = "https://api.github.com"
    token_env: str = "GITHUB_TOKEN"


class GitLabBackendConfig(BaseModel):
    api_url: str = "https://gitlab.com/api/v4"
    token_env: str = "GITLAB_TOKEN"


class GitConfig(BaseModel):
    """
    Pluggable git hosting for customer repos (not tool source on GitHub).

    Default bundled-forgejo keeps repos, PRs, diffs, and comments on-host.
    """

    backend: GitBackendKind = GitBackendKind.BUNDLED_FORGEJO
    # Required true for github/gitlab — confirms sovereignty tradeoff (docs/git-backends.md).
    external_sovereignty_acknowledged: bool = False
    bundled: GitBundledConfig = Field(default_factory=GitBundledConfig)
    github: GitHubBackendConfig = Field(default_factory=GitHubBackendConfig)
    gitlab: GitLabBackendConfig = Field(default_factory=GitLabBackendConfig)

    def is_sovereign(self) -> bool:
        return self.backend == GitBackendKind.BUNDLED_FORGEJO

    def token_env_name(self) -> str:
        if self.backend == GitBackendKind.BUNDLED_FORGEJO:
            return self.bundled.token_env
        if self.backend == GitBackendKind.GITHUB:
            return self.github.token_env
        return self.gitlab.token_env

    def token(self) -> str:
        return os.environ.get(self.token_env_name(), "")


# Deprecated alias — use git.bundled
ForgejoConfig = GitBundledConfig


class RoutingConfig(BaseModel):
    code_globs: list[str] = Field(
        default_factory=lambda: [
            "**/*.py",
            "**/*.go",
            "**/*.java",
            "**/*.js",
            "**/*.ts",
            "**/*.tsx",
            "**/*.c",
            "**/*.cpp",
            "**/*.h",
            "**/*.rs",
            "**/*.rb",
            "**/*.php",
        ]
    )
    config_globs: list[str] = Field(
        default_factory=lambda: [
            "**/*.yaml",
            "**/*.yml",
            "**/*.json",
            "**/*.tf",
            "**/*.tfvars",
            "**/Dockerfile*",
            "**/*.xml",
            "**/*.rules",
            "**/*.conf",
            "**/*.cfg",
        ]
    )
    ignore_globs: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/.git/**",
            "**/vendor/**",
            "**/*.min.js",
            "**/dist/**",
            "**/build/**",
            ".github/workflows/**",
            ".forgejo/workflows/**",
            "**/.github/workflows/**",
            "**/.forgejo/workflows/**",
        ]
    )
    pr_gate_exclusion_globs: list[str] = Field(
        default_factory=lambda: [
            "**/node_modules/**",
            "**/.git/**",
            "**/vendor/**",
            "**/*.min.js",
            "**/dist/**",
            "**/build/**",
            ".github/workflows/**",
            ".forgejo/workflows/**",
            "**/.github/workflows/**",
            "**/.forgejo/workflows/**",
        ],
        description=(
            "Changed paths matching these globs are explicitly excluded from PR gate "
            "coverage checks (pass without analysis). Must be enumerated in shift-left.yaml."
        ),
    )
    routing_parser_claim_globs: list[str] = Field(
        default_factory=lambda: list(
            __import__(
                "shift_left.handlers.config.parser_scope",
                fromlist=["ROUTING_PARSER_CLAIM_GLOBS"],
            ).ROUTING_PARSER_CLAIM_GLOBS
        ),
        validation_alias=AliasChoices("routing_parser_claim_globs", "deterministic_parser_globs"),
        description=(
            "ROUTING_PARSER_CLAIM_GLOBS: extensions claimable on the PR path without "
            "resolving a managed target (subset of config_globs). Per-target-only "
            "extensions such as **/*.cfg are omitted — those require managed-target "
            "resolution against TARGET_TYPE_PARSER_GLOBS. See also BLOCKING_POLICY_PATH_GLOBS "
            "for CWE block-policy scope (union of all per-target parser globs)."
        ),
    )


class ModelStageTimeouts(BaseModel):
    connect: float = 30.0
    load: float = 120.0
    prompt: float = 60.0
    generation: float = 300.0
    unload: float = 30.0


class EnrichmentConfig(BaseModel):
    enabled: bool = False
    enrich_findings: bool = True
    generate_review_summary: bool = True
    engine: Literal["scripted", "foundation_sec"] = "scripted"


class AntaresAgentConfig(BaseModel):
    engine: Literal["llm", "scripted"] = "llm"
    max_terminal_calls: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    loop_control_enabled: bool | None = None
    max_snapshot_bytes: int = 2_000_000
    recycle_after_runs: int = 10


class AntaresTriageConfig(BaseModel):
    enabled: bool = False
    installed: bool = False
    # Repo-relative. Compose bind-mounts ./data/repos → /data/repos (see SHIFT_LEFT_DATA_DIR).
    repos_checkout_dir: str = "data/repos"
    model_variant: str = "fdtn-ai/antares-1b"
    model_version: str | None = None
    minimum_variant: Literal["1b", "350m"] = "1b"
    scheduled_cwes: list[str] = Field(default_factory=list)
    scheduled_cwe_descriptions: dict[str, str] = Field(default_factory=dict)


class InvestigationBatchConfig(BaseModel):
    """Guardrails for POST /api/v1/investigations/batch (not merged findings)."""

    size_cap: int = 25
    confirm_threshold: int = 10


class InvestigationsStoreConfig(BaseModel):
    """Antares investigation persistence — separate from gate findings."""

    sqlite_path: str = "data/findings/investigations.db"
    retention_days: int = 90
    queue_depth_cap: int = 10
    queue_wait_timeout_minutes: int = 15
    batch: InvestigationBatchConfig = Field(default_factory=InvestigationBatchConfig)


class AntaresModelConfig(BaseModel):
    enabled: bool = False
    installed: bool = False
    local_path: str = "models/1b"
    backend: str = "auto"
    load_strategy: str = "resident_for_run"
    hf_repo_id: str = "fdtn-ai/antares-1b"
    max_context_tokens: int = 8192
    max_hunk_lines: int = 200
    service_url: str = "http://antares-server:8090"
    request_timeout_seconds: int = 600
    stage_timeouts: ModelStageTimeouts = Field(default_factory=ModelStageTimeouts)
    agent: AntaresAgentConfig = Field(default_factory=AntaresAgentConfig)


class FoundationSecModelConfig(BaseModel):
    enabled: bool = True
    # instruct (default) | reasoning — separate GGUF profiles, never interchangeable.
    model_variant: Literal["instruct", "reasoning"] = "instruct"
    local_path: str = "models/foundation-sec-q8_0"
    local_path_low_memory: str = "models/foundation-sec-q4_k_m"
    local_path_reasoning: str = "models/foundation-sec-reasoning-q4_k_m"
    hf_repo_id: str = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q8_0-GGUF"
    hf_repo_id_low_memory: str = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct-Q4_K_M-GGUF"
    hf_repo_id_reasoning: str = "fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF"
    gguf_glob: str = "foundation-sec-1.1-8b-instruct-q8_0.gguf"
    gguf_glob_low_memory: str = "foundation-sec-1.1-8b-instruct-q4_k_m.gguf"
    gguf_glob_reasoning: str = "foundation-sec-8b-reasoning-q4_k_m.gguf"
    quant_label: str = "default"
    quant_label_low_memory: str = "low-memory"
    quant_label_reasoning: str = "reasoning-q4_k_m"
    use_low_memory: bool = True
    backend: str = "auto"
    load_strategy: str = "on_demand"
    service_url: str = "http://foundation-sec-server:8091"
    max_context_tokens: int = 4096
    max_context_tokens_reasoning: int = 16384
    max_hunk_lines: int = 500
    context_lines_before: int = 5
    context_lines_after: int = 5
    chunk_overlap_lines: int = 2
    prompt_scaffold_tokens: int = 768
    max_output_tokens: int = 1024
    max_output_tokens_reasoning: int = 8192
    safety_margin_tokens: int = 128
    request_timeout_seconds: int = 600
    stage_timeouts: ModelStageTimeouts = Field(default_factory=ModelStageTimeouts)


class ModelsConfig(BaseModel):
    antares: AntaresModelConfig = Field(default_factory=AntaresModelConfig)
    foundation_sec: FoundationSecModelConfig = Field(default_factory=FoundationSecModelConfig)


class FindingsStoreConfig(BaseModel):
    type: str = "sqlite"
    sqlite_path: str = "data/findings/shift-left.db"
    postgres_url: str | None = None


class ApprovalConfig(BaseModel):
    """Human approval rules — separation of duties default deny."""

    separation_of_duties_enforced: bool = True


class UnclaimedFilesGateConfig(BaseModel):
    """Gate policy for changed files outside code/config globs.

    Emits CWE-657 findings (``policy_severity=high``, default BLOCK policy).
    Sibling policy ``block-uninterpretable-config`` blocks CWE-754 (ASA-007, HCL-001) for
    lines inside claimed config files that the parser cannot represent.
    """

    enabled: bool = True
    handler_asserted_cwe: str = "CWE-657"
    policy_action: PolicyAction = PolicyAction.BLOCK
    waivable: bool = False


class GateConfig(BaseModel):
    """Commit status gate — independent of CI workflow files."""

    enabled: bool = True
    protected_branch: str = "main"
    status_context: str = "shift-left/gate"
    publish_commit_status: bool = True
    warn_if_branch_protection_missing: bool = True
    # owner/repo slug used for startup branch-protection self-check (optional).
    check_repo: str | None = None
    unclaimed_files: UnclaimedFilesGateConfig = Field(default_factory=UnclaimedFilesGateConfig)


class AdvisorySuppressionConfig(BaseModel):
    """Keep model-only findings in the UI; omit them from CI/PR gate surfaces."""

    omit_from_pr_comments: bool = True
    omit_from_review_api: bool = True


class LegacyPathRewrite(BaseModel):
    """Operator YAML used a legacy container-absolute data path that was remapped."""

    key: str
    original: str
    resolved: str


class AuthConfig(BaseModel):
    """API token storage — hashed at rest, never plaintext."""

    sqlite_path: str | None = None


class PolicyConfig(BaseModel):
    human_review_required: bool = True
    default_action: PolicyAction = PolicyAction.FLAG
    rules: list[Policy] = Field(default_factory=lambda: _default_policy_rules())
    allow_block_override: bool = False
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    cwe_severity_mapping: dict[str, str] = Field(default_factory=dict)
    pattern_severity_mapping: dict[str, str] = Field(default_factory=dict)
    operator_escalations: list[OperatorEscalation] = Field(default_factory=list)


def _default_policy_rules() -> list[Policy]:
    """Default gate policy: block handler-classified unrestricted ingress and unclaimed paths."""
    return [
        Policy(
            id="block-unrestricted-ingress",
            name="Block unrestricted ingress (handler CWE-284)",
            applies_to=PolicyAppliesTo(
                target_kind=TargetKind.CONFIG,
                path_globs=_parser_scoped_blocking_path_globs(),
            ),
            rules=[PolicyRule(cwe_blocklist=["CWE-284"])],
            action=PolicyAction.BLOCK,
            enabled=True,
        ),
        Policy(
            id="block-unclaimed-changed-files",
            name="Block PR changes outside declared review scope (handler CWE-657)",
            applies_to=PolicyAppliesTo(path_globs=["**/*"]),
            rules=[PolicyRule(cwe_blocklist=["CWE-657"])],
            action=PolicyAction.BLOCK,
            enabled=True,
        ),
        Policy(
            id="block-uninterpretable-config",
            name="Block uninterpretable config statements (handler CWE-754)",
            applies_to=PolicyAppliesTo(
                target_kind=TargetKind.CONFIG,
                path_globs=_parser_scoped_blocking_path_globs(),
            ),
            rules=[PolicyRule(cwe_blocklist=["CWE-754"])],
            action=PolicyAction.BLOCK,
            enabled=True,
        ),
    ]


class AuditConfig(BaseModel):
    """
    Append-only audit log.

    Pruning is operator-initiated only (shift-left audit-prune) — never automatic.
    """

    retention_days: int = 365
    sqlite_path: str | None = None


class OrchestratorConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080
    concurrency: int = 2
    comment_prefix: str = ""
    # Force "docker compose" or "docker-compose"; None auto-detects at startup.
    compose_command: str | None = None


class UiConfig(BaseModel):
    """Local web UI — loopback-only by default; no external assets."""

    enabled: bool = True
    require_loopback_client: bool = True
    allow_remote_view: bool = False


class RbacConfig(BaseModel):
    """
    Development-only RBAC overrides.

    allow_self_approval: when true, commit author may approve their own change.
    Unsuitable for production — requires persistent UI banner and audit on every approval.
    """

    allow_self_approval: bool = False


class FmcPlanDeploymentConfig(BaseModel):
    """Plan-only FMC Terraform — no apply in this phase."""

    enabled: bool = False
    terraform_workdir: str = "examples/ftdv-firewall/terraform"
    # TODO: verify Terraform + CiscoDevNet/fmc provider versions against lab FMC.
    terraform_bin: str = "terraform"
    target_label: str = "fmc-lab"
    password_env: str = "TF_VAR_fmc_password"
    username_env: str = "TF_VAR_fmc_username"
    host_env: str = "TF_VAR_fmc_host"
    allowed_endpoint: str | None = None  # host:port for FMC management plane


class DeploymentConfig(BaseModel):
    mode: Literal["plan_only", "dry_run"] = "plan_only"
    fmc: FmcPlanDeploymentConfig = Field(default_factory=FmcPlanDeploymentConfig)


class ResourcesConfig(BaseModel):
    max_diff_bytes: int = 5_242_880
    max_files_per_review: int = 100


class ManagedTargetConfig(BaseModel):
    """Declared device/system target — never inferred from repository names."""

    id: str
    display_name: str
    target_type: str
    description: str = ""
    repo: str
    branch: str = "main"
    config_paths: list[str]
    deployment_adapter: str = "unconfigured"
    deployment_adapter_settings: dict[str, Any] = Field(default_factory=dict)
    environment: str = ""
    criticality: str = ""
    owner: str = ""


class ManagedTargetsConfig(BaseModel):
    targets: list[ManagedTargetConfig] = Field(default_factory=list)
    applied_revisions: list[AppliedRevision] = Field(default_factory=list)


class AppConfig(BaseModel):
    schema_version: int = CURRENT_SCHEMA_VERSION
    distribution: DistributionConfig = Field(default_factory=DistributionConfig)
    sovereignty: SovereigntyConfig = Field(default_factory=SovereigntyConfig)
    reference_data: ReferenceDataConfig = Field(default_factory=ReferenceDataConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    git: GitConfig = Field(default_factory=GitConfig)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    models: ModelsConfig = Field(default_factory=ModelsConfig)
    antares_triage: AntaresTriageConfig = Field(default_factory=AntaresTriageConfig)
    investigations: InvestigationsStoreConfig = Field(default_factory=InvestigationsStoreConfig)
    findings_store: FindingsStoreConfig = Field(default_factory=FindingsStoreConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    gate: GateConfig = Field(default_factory=GateConfig)
    advisory_suppression: AdvisorySuppressionConfig = Field(default_factory=AdvisorySuppressionConfig)
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    ui: UiConfig = Field(default_factory=UiConfig)
    rbac: RbacConfig = Field(default_factory=RbacConfig)
    resources: ResourcesConfig = Field(default_factory=ResourcesConfig)
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)
    managed_targets: ManagedTargetsConfig = Field(default_factory=ManagedTargetsConfig)
    # Runtime-only: populated by load_config when YAML used /shift-left/data or /data.
    legacy_path_rewrites: list[LegacyPathRewrite] = Field(default_factory=list, exclude=True)

    @property
    def forgejo(self) -> GitBundledConfig:
        """Deprecated: use config.git.bundled."""
        return self.git.bundled

    @model_validator(mode="after")
    def _apply_unclaimed_gate_policy(self) -> Self:
        gate = self.gate.unclaimed_files
        updated_rules: list[Policy] = []
        for policy in self.policy.rules:
            if policy.id != "block-unclaimed-changed-files":
                updated_rules.append(policy)
                continue
            updated_rules.append(
                policy.model_copy(
                    update={
                        "enabled": gate.enabled,
                        "action": gate.policy_action,
                        "rules": [PolicyRule(cwe_blocklist=[gate.handler_asserted_cwe])],
                    }
                )
            )
        return self.model_copy(update={"policy": self.policy.model_copy(update={"rules": updated_rules})})


def _nested_get(raw: dict[str, Any], *keys: str) -> Any:
    current: Any = raw
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _validate_config_schema(raw: dict[str, Any], config_path: Path) -> None:
    """Reject stale operator configs before they silently misconfigure runtime."""
    version = raw.get("schema_version")
    if version is None:
        raise ValueError(
            f"{config_path}: missing required schema_version (expected {CURRENT_SCHEMA_VERSION}). "
            "Copy config/shift-left.example.yaml and merge your local settings."
        )
    if version != CURRENT_SCHEMA_VERSION:
        raise ValueError(
            f"{config_path}: unsupported schema_version {version!r} "
            f"(expected {CURRENT_SCHEMA_VERSION})."
        )

    stale_keys: list[str] = []
    if _nested_get(raw, "models", "foundation_sec", "quant") is not None:
        stale_keys.append("models.foundation_sec.quant")
    if _nested_get(raw, "models", "foundation_sec", "quant_low_memory") is not None:
        stale_keys.append("models.foundation_sec.quant_low_memory")
    if "runtime_allowed_hosts" in (raw.get("sovereignty") or {}):
        stale_keys.append("sovereignty.runtime_allowed_hosts")

    if stale_keys:
        raise ValueError(
            f"{config_path}: stale configuration keys: {', '.join(stale_keys)}. "
            "Use schema_version 11 fields (investigations.queue_wait_timeout_minutes, "
            "pr_gate_exclusion_globs, gate.unclaimed_files). "
            "See config/shift-left.example.yaml."
        )

    if version == 3:
        raise ValueError(
            f"{config_path}: schema_version 3 is no longer supported "
            f"(expected {CURRENT_SCHEMA_VERSION}). "
            "Add enrichment section and bump schema_version — see config/shift-left.example.yaml."
        )

    fs = raw.get("models", {}).get("foundation_sec")
    if isinstance(fs, dict) and fs.get("enabled", True):
        if "gguf_glob" not in fs:
            raise ValueError(
                f"{config_path}: models.foundation_sec.gguf_glob is required "
                "(replaces deprecated quant fields)."
            )


def _migrate_legacy_config(raw: dict[str, Any]) -> dict[str, Any]:
    if "git" not in raw and "forgejo" in raw:
        raw = dict(raw)
        raw["git"] = {
            "backend": "bundled-forgejo",
            "bundled": raw.pop("forgejo"),
        }
    return raw


def _repo_root_for_config(config_path: Path) -> Path:
    """Repo root used to resolve yaml-relative paths.

    ``SHIFT_LEFT_CONFIG=/config/shift-left.yaml`` is a Compose file bind-mount.
    Its parent is named ``config`` but parent.parent is ``/``, not the repo.
    Prefer ``SHIFT_LEFT_REPO_ROOT`` (set to ``/shift-left`` in Compose).
    """
    env_root = os.environ.get("SHIFT_LEFT_REPO_ROOT", "").strip()
    if env_root:
        candidate = Path(env_root)
        if candidate.is_dir():
            return candidate.resolve()
        return candidate
    resolved = config_path.resolve()
    if resolved.parent.name == "config":
        parent = resolved.parent.parent
        if parent != Path(parent.anchor):
            return parent
        return _repo_root_from_package()
    return resolved.parent


def _as_repo_relative_data_path(path_str: str, repo_root: Path) -> str | None:
    """Map a storage path onto the ``data/...`` prefix, including legacy container paths."""
    candidate = Path(path_str)
    posix = candidate.as_posix()
    if not candidate.is_absolute():
        if posix == "data" or posix.startswith("data/"):
            return posix
        return None

    prefixes = [
        "/shift-left/data/",
        "/data/",
        f"{(repo_root / 'data').as_posix()}/",
    ]
    try:
        prefixes.append(f"{(repo_root / 'data').resolve().as_posix()}/")
    except OSError:
        pass
    container_root = os.environ.get("SHIFT_LEFT_REPO_ROOT", "").strip()
    if container_root:
        prefixes.append(f"{(Path(container_root) / 'data').as_posix()}/")

    seen: set[str] = set()
    for prefix in prefixes:
        if prefix in seen:
            continue
        seen.add(prefix)
        if posix == prefix.rstrip("/"):
            return "data"
        if posix.startswith(prefix):
            rest = posix[len(prefix) :]
            return f"data/{rest}" if rest else "data"
    return None


def _resolve_storage_path(path_str: str, repo_root: Path) -> str:
    """Resolve findings/reference/repos paths for host-native CLI and Compose.

    YAML stores repo-relative ``data/...`` paths. Inside Compose, ``SHIFT_LEFT_DATA_DIR=/data``
    maps those onto the dedicated volumes (``./data/findings:/data/findings``, etc.).
    The repo bind-mount ``.:/shift-left:ro`` is not writable, so sqlite and checkouts
    must not resolve to ``/shift-left/data/...``.
    """
    data_relative = _as_repo_relative_data_path(path_str, repo_root)
    if data_relative is None:
        candidate = Path(path_str)
        if candidate.is_absolute():
            return path_str
        return str((repo_root / candidate).resolve())
    rest = data_relative[len("data/") :] if data_relative.startswith("data/") else ""
    data_dir = os.environ.get("SHIFT_LEFT_DATA_DIR", "").strip()
    if data_dir:
        return str(Path(data_dir) / rest) if rest else str(Path(data_dir))
    return str((repo_root / data_relative).resolve())


def _is_legacy_container_data_path(path_str: str) -> bool:
    """True for operator YAML that still uses /shift-left/data/... or /data/..."""
    posix = Path(path_str).as_posix()
    for root in _LEGACY_CONTAINER_DATA_ROOTS:
        if posix == root or posix.startswith(f"{root}/"):
            return True
    return False


def _maybe_legacy_rewrite(key: str, original: str, resolved: str) -> LegacyPathRewrite | None:
    if not _is_legacy_container_data_path(original):
        return None
    if Path(original).as_posix() == Path(resolved).as_posix():
        return None
    return LegacyPathRewrite(key=key, original=original, resolved=resolved)


def _assign_storage_path(
    mapping: dict[str, Any],
    field: str,
    key: str,
    repo_root: Path,
    rewrites: list[LegacyPathRewrite],
) -> None:
    original = str(mapping[field])
    resolved = _resolve_storage_path(original, repo_root)
    mapping[field] = resolved
    rewrite = _maybe_legacy_rewrite(key, original, resolved)
    if rewrite is not None:
        rewrites.append(rewrite)


def _resolve_config_paths(
    raw: dict[str, Any], config_path: Path
) -> tuple[dict[str, Any], list[LegacyPathRewrite]]:
    """Resolve repo-relative storage paths so native and container runs share one yaml."""
    base = _repo_root_for_config(config_path)
    resolved = dict(raw)
    rewrites: list[LegacyPathRewrite] = []

    sovereignty = resolved.get("sovereignty")
    if isinstance(sovereignty, dict):
        sovereignty = dict(sovereignty)
        assets: list[dict[str, str]] = []
        for index, asset in enumerate(sovereignty.get("required_assets") or []):
            if not isinstance(asset, dict):
                assets.append(asset)
                continue
            entry = dict(asset)
            if "path" in entry:
                _assign_storage_path(
                    entry, "path", f"sovereignty.required_assets[{index}].path", base, rewrites
                )
            assets.append(entry)
        sovereignty["required_assets"] = assets
        resolved["sovereignty"] = sovereignty

    reference = resolved.get("reference_data")
    if isinstance(reference, dict) and reference.get("cache_dir"):
        reference = dict(reference)
        _assign_storage_path(
            reference, "cache_dir", "reference_data.cache_dir", base, rewrites
        )
        resolved["reference_data"] = reference

    findings = resolved.get("findings_store")
    if isinstance(findings, dict) and findings.get("sqlite_path"):
        findings = dict(findings)
        _assign_storage_path(
            findings, "sqlite_path", "findings_store.sqlite_path", base, rewrites
        )
        resolved["findings_store"] = findings

    auth = resolved.get("auth")
    if isinstance(auth, dict) and auth.get("sqlite_path"):
        auth = dict(auth)
        _assign_storage_path(auth, "sqlite_path", "auth.sqlite_path", base, rewrites)
        resolved["auth"] = auth

    audit = resolved.get("audit")
    if isinstance(audit, dict) and audit.get("sqlite_path"):
        audit = dict(audit)
        _assign_storage_path(audit, "sqlite_path", "audit.sqlite_path", base, rewrites)
        resolved["audit"] = audit

    triage = resolved.get("antares_triage")
    if isinstance(triage, dict) and triage.get("repos_checkout_dir"):
        triage = dict(triage)
        _assign_storage_path(
            triage, "repos_checkout_dir", "antares_triage.repos_checkout_dir", base, rewrites
        )
        resolved["antares_triage"] = triage

    investigations = resolved.get("investigations")
    if isinstance(investigations, dict) and investigations.get("sqlite_path"):
        investigations = dict(investigations)
        _assign_storage_path(
            investigations, "sqlite_path", "investigations.sqlite_path", base, rewrites
        )
        resolved["investigations"] = investigations

    # Model weight paths stay repo-relative (``models/...``). Supervisors and
    # inventory join them onto SHIFT_LEFT_REPO_ROOT; they are not under /data.

    return resolved, rewrites


def _repo_root_from_package() -> Path:
    """Repository root (shift-left/) from this module's install path."""
    return Path(__file__).resolve().parent.parent.parent.parent


def _config_search_paths(requested: Path) -> list[Path]:
    repo_root = _repo_root_from_package()
    filename = requested.name
    example_name = "shift-left.example.yaml"
    return [
        requested,
        repo_root / "config" / filename,
        requested.parent / example_name,
        repo_root / "config" / example_name,
    ]


def resolve_repo_root() -> Path:
    """Repository root (shift-left/) regardless of process working directory."""
    env_root = os.environ.get("SHIFT_LEFT_REPO_ROOT", "").strip()
    if env_root:
        candidate = Path(env_root)
        if candidate.is_dir():
            return candidate.resolve()
    return _repo_root_from_package()


def resolve_repo_relative_path(path_str: str) -> Path:
    """Join a yaml path onto the repo root; leave already-absolute paths unchanged."""
    path = Path(path_str)
    if path.is_absolute():
        return path
    return resolve_repo_root() / path


def resolve_config_path(path: str | Path | None = None) -> Path:
    """Locate operator config regardless of process working directory."""
    requested = Path(path or os.environ.get("SHIFT_LEFT_CONFIG", "config/shift-left.yaml"))
    for candidate in _config_search_paths(requested):
        if candidate.is_file():
            return candidate.resolve()
    searched = ", ".join(str(item) for item in _config_search_paths(requested))
    raise FileNotFoundError(
        f"Shift-Left config not found (looked for {requested.name}). "
        f"Searched: {searched}. "
        "Copy config/shift-left.example.yaml to config/shift-left.yaml or set SHIFT_LEFT_CONFIG."
    )


def load_config(path: str | Path | None = None) -> AppConfig:
    config_path = resolve_config_path(path)
    with config_path.open() as handle:
        raw = yaml.safe_load(handle) or {}

    raw = _migrate_legacy_config(raw)
    _validate_config_schema(raw, config_path)
    raw, rewrites = _resolve_config_paths(raw, config_path)
    raw_policy = raw.get("policy") or {}
    if isinstance(raw_policy, dict):
        from shift_left.policy.loader import validate_raw_policies

        validate_raw_policies(list(raw_policy.get("rules") or []))
    config = AppConfig.model_validate(raw).model_copy(update={"legacy_path_rewrites": rewrites})
    from shift_left.targets.validation import ManagedTargetConfigError, validate_managed_targets

    try:
        validate_managed_targets(config.managed_targets.targets, routing=config.routing)
    except ManagedTargetConfigError as exc:
        raise ValueError(f"{config_path}: {exc}") from exc
    for rewrite in config.legacy_path_rewrites:
        logger.warning(
            "legacy config path rewritten: %s %r -> %r",
            rewrite.key,
            rewrite.original,
            rewrite.resolved,
        )
    return config


def resolve_antares_service_url(config: AppConfig) -> str:
    """Allow host-native Antares on macOS via env override."""
    return os.environ.get("ANTARES_SERVICE_URL", config.models.antares.service_url)


def resolve_foundation_sec_service_url(config: AppConfig) -> str:
    return os.environ.get(
        "FOUNDATION_SEC_SERVICE_URL",
        config.models.foundation_sec.service_url,
    )


def resolve_audit_sqlite_path(config: AppConfig) -> str:
    if config.audit.sqlite_path:
        return config.audit.sqlite_path
    return config.findings_store.sqlite_path


def resolve_auth_sqlite_path(config: AppConfig) -> str:
    if config.auth.sqlite_path:
        return config.auth.sqlite_path
    return config.findings_store.sqlite_path


def effective_cwe_severity_mapping(config: AppConfig) -> dict[str, str]:
    from shift_left.policy.severity import default_cwe_severity_mapping

    merged = default_cwe_severity_mapping()
    merged.update(config.policy.cwe_severity_mapping)
    return merged


def runtime_allowed_endpoints(config: AppConfig) -> frozenset[AllowedEndpoint]:
    from shift_left.git.factory import git_http_allowed_endpoints

    return git_http_allowed_endpoints(config)


def runtime_allowed_hosts(config: AppConfig) -> frozenset[str]:
    """Deprecated — prefer runtime_allowed_endpoints()."""
    return frozenset(host for host, _port in runtime_allowed_endpoints(config))
