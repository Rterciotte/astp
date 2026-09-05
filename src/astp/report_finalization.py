from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from astp.assessment_manifest import AssessmentManifest, verify_assessment_manifest
from astp.operator_review import OperatorReview, ReviewDecision


class ReportFinalization(BaseModel):
    schema_version: str = "1"
    manifest_hash: str
    review_decision: ReviewDecision
    report_sha256: str
    finalized_at: datetime
    publishable: bool


def finalize_report(
    manifest: AssessmentManifest,
    review: OperatorReview,
    report_path: Path,
) -> ReportFinalization:
    if not verify_assessment_manifest(manifest):
        raise ValueError("assessment manifest integrity failed")
    if review.assessment_manifest_hash != manifest.manifest_hash:
        raise ValueError("operator review is bound to a different assessment")
    report_hash = hashlib.sha256(report_path.read_bytes()).hexdigest()
    if manifest.report_sha256 and manifest.report_sha256 != report_hash:
        raise ValueError("report hash differs from the reviewed assessment manifest")
    return ReportFinalization(
        manifest_hash=manifest.manifest_hash,
        review_decision=review.decision,
        report_sha256=report_hash,
        finalized_at=datetime.now(UTC),
        publishable=review.decision == ReviewDecision.APPROVE,
    )
