from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from astp.findings import FindingSet
from astp.fingerprint import TechnologyFingerprint
from astp.models import Engagement
from astp.reporting import render_markdown_report
from astp.signal_normalizer import NormalizedSignal


class AssessmentReportInput(BaseModel):
    fingerprints: list[TechnologyFingerprint] = Field(default_factory=list)
    signals: list[NormalizedSignal] = Field(default_factory=list)
    findings: FindingSet = Field(default_factory=FindingSet)
    limitations: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


def assemble_assessment_report(
    engagement: Engagement,
    assessment: AssessmentReportInput,
    *,
    now: datetime | None = None,
) -> str:
    generated = now or datetime.now(UTC)
    base = render_markdown_report(engagement, assessment.findings, now=generated)
    prefix = [
        f"# ASTP Assessment Record — {engagement.name}",
        "",
        f"Generated: {generated.isoformat()}",
        "",
        "## Scope and safety",
        "",
        f"Allowed scope rules: {len(engagement.scope.allowed)}",
        f"Denied scope rules: {len(engagement.scope.denied)}",
        "Only policy-authorized, permit-gated execution may produce target-side evidence.",
        "",
        "## Technology fingerprint",
        "",
    ]
    technologies = sorted(
        {
            technology
            for fingerprint in assessment.fingerprints
            for technology in fingerprint.technologies
        }
    )
    prefix.extend(
        [f"- {item}" for item in technologies] or ["- No technology fingerprint available."]
    )
    prefix.extend(
        [
            "",
            "## Evidence and signal summary",
            "",
            f"Evidence records: {len(set(assessment.evidence_ids))}",
            f"Normalized signals: {len(assessment.signals)}",
            "",
            "## Limitations",
            "",
        ]
    )
    prefix.extend([f"- {item}" for item in assessment.limitations] or ["- None recorded."])
    prefix.extend(["", "## Finding report", ""])
    return "\n".join(prefix) + base
