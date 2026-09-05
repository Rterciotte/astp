from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, Field

from astp.assessment_coverage import AssessmentCoverage, current_assessment_coverage
from astp.assessment_cycle import plan_safe_surface_observations
from astp.auth_session import AuthSessionProfile


class EndToEndAssessmentPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    engagement_id: str
    initial_target: str
    safe_surface_action_count: int
    auth_session_id: str | None = None
    coverage: AssessmentCoverage
    requires_operator_review_for_high_risk: bool = True
    execution_enabled: bool = False
    unresolved_capabilities: tuple[str, ...] = Field(default_factory=tuple)


def build_end_to_end_assessment_plan(
    engagement_id: str,
    initial_target: str,
    *,
    auth_session: AuthSessionProfile | None = None,
) -> EndToEndAssessmentPlan:
    surface = plan_safe_surface_observations(initial_target)
    coverage = current_assessment_coverage()
    blockers: list[str] = []
    if not coverage.authorization_differential:
        blockers.append("authorization differential execution")
    if not coverage.browser_dynamic:
        blockers.append("isolated browser worker")
    if not coverage.external_adapters:
        blockers.append("permit-gated external adapters")
    if not coverage.active_verification:
        blockers.append("broad vulnerability-specific active verification")
    digest = hashlib.sha256(f"{engagement_id}|{initial_target}".encode()).hexdigest()[:16]
    return EndToEndAssessmentPlan(
        id=f"assessment-plan-{digest}",
        engagement_id=engagement_id,
        initial_target=initial_target,
        safe_surface_action_count=len(surface.actions),
        auth_session_id=auth_session.id if auth_session else None,
        coverage=coverage,
        unresolved_capabilities=tuple(blockers),
    )
