from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from astp.feedback import FeedbackResult, apply_evidence_feedback
from astp.models import Engagement
from astp.observation import HttpObservationEvidence
from astp.target_registry import TargetRegistry


class SessionFeedback(BaseModel):
    session_id: str
    evidence_id: str
    applied_at: datetime
    added_targets: int
    candidate_ids: list[str] = Field(default_factory=list)
    registry: TargetRegistry


def apply_session_feedback(
    session_id: str,
    evidence: HttpObservationEvidence,
    engagement: Engagement,
    registry: TargetRegistry,
    *,
    max_candidates: int = 50,
    now: datetime | None = None,
) -> SessionFeedback:
    if evidence.engagement_id != engagement.id or registry.engagement_id != engagement.id:
        raise ValueError("feedback objects belong to different engagements")
    result: FeedbackResult = apply_evidence_feedback(
        evidence, engagement, registry, max_candidates=max_candidates
    )
    return SessionFeedback(
        session_id=session_id,
        evidence_id=evidence.evidence_id,
        applied_at=now or datetime.now(UTC),
        added_targets=result.added_entries,
        candidate_ids=[item.id for item in result.discovered.candidates],
        registry=result.registry,
    )
