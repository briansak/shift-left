"""Resolve secret values for stored findings at presentation time."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from shift_left.handlers.config.secret_values import (
    SecretValueSet,
    extract_secret_values_from_content,
)
from shift_left.models.schema import Finding
from shift_left.ui.config_redaction import FINDING_CONFIG_TEXT_FIELDS

ValueRedactionSource = Literal["commit_file", "finding_fields", "unavailable"]

FileContentCache = dict[tuple[str, str, str], str]


@dataclass
class SecretResolutionCache:
    """Request-scoped cache for git file reads during finding serialization."""

    file_content: FileContentCache = field(default_factory=dict)


@dataclass(frozen=True)
class ValueRedactionProvenance:
    finding_id: str
    source: ValueRedactionSource
    commit_sha: str | None = None
    file_path: str | None = None
    message: str | None = None


def _finding_field_blob(finding: Finding) -> str:
    parts: list[str] = []
    for field in FINDING_CONFIG_TEXT_FIELDS:
        value = getattr(finding, field, None)
        if value:
            parts.append(str(value))
    return "\n".join(parts)


def secrets_from_finding_fields(finding: Finding) -> SecretValueSet:
    return extract_secret_values_from_content(
        _finding_field_blob(finding),
        path=finding.file_path,
    )


def provenance_for_finding_fields(finding: Finding) -> ValueRedactionProvenance:
    return ValueRedactionProvenance(
        finding_id=finding.id,
        source="finding_fields",
        commit_sha=finding.commit_sha,
        file_path=finding.file_path,
        message="Secret values derived from finding presentation fields only (no git re-read).",
    )


def _split_repo(repo_slug: str) -> tuple[str, str]:
    owner, repo = repo_slug.split("/", 1)
    return owner, repo


async def _load_file_at_commit(
    finding: Finding,
    git: Any,
    cache: SecretResolutionCache | None,
) -> str | None:
    get_file = getattr(git, "get_file_content", None)
    if get_file is None or not finding.file_path or not finding.commit_sha:
        return None
    cache_key = (finding.repo, finding.commit_sha, finding.file_path)
    if cache is not None and cache_key in cache.file_content:
        return cache.file_content[cache_key]
    owner, repo_name = _split_repo(finding.repo)
    try:
        content = await get_file(owner, repo_name, finding.file_path, finding.commit_sha)
    except Exception:
        content = ""
    if cache is not None:
        cache.file_content[cache_key] = content
    return content


async def resolve_secret_values_for_finding(
    finding: Finding,
    git: Any,
    *,
    cache: SecretResolutionCache | None = None,
) -> tuple[SecretValueSet, ValueRedactionProvenance]:
    """Load secret values for a stored finding.

    Order: re-read ``file_path`` at ``commit_sha`` from git when possible;
    always merge values extracted from the finding's own presentation fields.
    """
    field_secrets = secrets_from_finding_fields(finding)
    content = await _load_file_at_commit(finding, git, cache)
    if content is None:
        source = "finding_fields" if field_secrets.redactable or field_secrets.ambiguous else "unavailable"
        return field_secrets, ValueRedactionProvenance(
            finding_id=finding.id,
            source=source,
            commit_sha=finding.commit_sha,
            file_path=finding.file_path,
            message=(
                None
                if source == "finding_fields"
                else "No git client or finding identity — value redaction uses directive/prose patterns only"
            ),
        )
    if not content or content.startswith("(unable"):
        merged = field_secrets
        source: ValueRedactionSource = (
            "finding_fields" if merged.redactable or merged.ambiguous else "unavailable"
        )
        return merged, ValueRedactionProvenance(
            finding_id=finding.id,
            source=source,
            commit_sha=finding.commit_sha,
            file_path=finding.file_path,
            message=(
                "Config file not resolvable at recorded commit SHA — "
                "value redaction limited to finding fields and directive/prose patterns"
                if source != "commit_file"
                else None
            ),
        )
    file_secrets = extract_secret_values_from_content(content, path=finding.file_path)
    merged = file_secrets.merge(field_secrets)
    return merged, ValueRedactionProvenance(
        finding_id=finding.id,
        source="commit_file",
        commit_sha=finding.commit_sha,
        file_path=finding.file_path,
    )


async def build_secret_index_for_findings(
    findings: list[Finding],
    git: Any,
    *,
    cache: SecretResolutionCache | None = None,
) -> tuple[dict[tuple[str, str], SecretValueSet], list[ValueRedactionProvenance]]:
    """Build per-(commit_sha, file_path) secret index; one git read per unique file ref."""
    index: dict[tuple[str, str], SecretValueSet] = {}
    provenance: list[ValueRedactionProvenance] = []
    for finding in findings:
        secrets, prov = await resolve_secret_values_for_finding(finding, git, cache=cache)
        key = (finding.commit_sha, finding.file_path)
        index[key] = secrets
        if prov.source != "commit_file":
            provenance.append(prov)
    return index, provenance


def secrets_for_indexed_finding(
    finding: Finding,
    index: dict[tuple[str, str], SecretValueSet],
) -> SecretValueSet:
    key = (finding.commit_sha, finding.file_path)
    base = index.get(key, SecretValueSet.empty())
    return base.merge(secrets_from_finding_fields(finding))
