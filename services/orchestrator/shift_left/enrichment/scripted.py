"""Deterministic enrichment prose for offline development and tests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shift_left.models.schema import Finding, ReviewSummary


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ScriptedEnrichmentEngine:
    """
    FIXTURE prose generator — clearly marked deterministic output for tests.

    Not model inference; do not treat output as authoritative security guidance.
    """

    generator_id = "scripted-fixture"

    def enrich_finding(self, finding: Finding) -> dict[str, Any]:
        return {
            "finding_id": finding.id,
            "model_context": (
                "[FIXTURE] Context for human reviewers: "
                f"{finding.title} in `{finding.file_path}` "
                f"(model severity `{finding.model_asserted_severity.value}`)."
            ),
            "recommended_actions": [
                "[FIXTURE] Review the changed hunk with your team's security checklist.",
                "[FIXTURE] Confirm whether least-privilege alternatives exist before merge.",
            ],
            "enrichment_source": self.generator_id,
            "enrichment_generated_at": _utc_now().isoformat(),
        }

    def enrich_findings(self, findings: list[Finding]) -> list[dict[str, Any]]:
        return [self.enrich_finding(finding) for finding in findings]

    def generate_review_summary(self, findings: list[Finding]) -> ReviewSummary:
        covered = [finding.id for finding in findings]
        if not findings:
            return ReviewSummary(
                summary_text=(
                    "[FIXTURE] No likely findings were reported for the changed hunks. "
                    "This summary is advisory fixture prose only."
                ),
                suggested_course_of_action=(
                    "[FIXTURE] Proceed with your normal human review process for this change."
                ),
                findings_covered=[],
                generated_at=_utc_now(),
                generator=self.generator_id,
            )

        titles = ", ".join(finding.title for finding in findings[:5])
        return ReviewSummary(
            summary_text=(
                "[FIXTURE] Reviewer summary covering "
                f"{len(findings)} likely finding(s): {titles}. "
                "Advisory fixture prose — not a policy or compliance verdict."
            ),
            suggested_course_of_action=(
                "[FIXTURE] Prioritize remediation discussion for flagged hunks "
                "and record rationale in your issue tracker."
            ),
            findings_covered=covered,
            generated_at=_utc_now(),
            generator=self.generator_id,
        )
