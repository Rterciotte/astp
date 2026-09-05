from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.assessment_manifest import AssessmentManifest, verify_assessment_manifest


class ReviewDecision(str, Enum):
    APPROVE = "approve"
    REJECT = "reject"
    NEEDS_CHANGES = "needs_changes"


class OperatorReview(BaseModel):
    schema_version: str = "1"
    assessment_manifest_hash: str
    reviewer: str
    decision: ReviewDecision
    reviewed_at: datetime
    notes: list[str] = Field(default_factory=list)


def record_operator_review(
    manifest: AssessmentManifest,
    reviewer: str,
    decision: ReviewDecision,
    *,
    notes: list[str] | None = None,
) -> OperatorReview:
    if not verify_assessment_manifest(manifest):
        raise ValueError("assessment manifest integrity verification failed")
    if not reviewer.strip():
        raise ValueError("reviewer is required")
    return OperatorReview(
        assessment_manifest_hash=manifest.manifest_hash,
        reviewer=reviewer.strip(),
        decision=decision,
        reviewed_at=datetime.now(UTC),
        notes=notes or [],
    )
