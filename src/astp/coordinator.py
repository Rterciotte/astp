from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CoordinatorStage(StrEnum):
    INTAKE = "intake"
    DISCOVERY = "discovery"
    OBSERVATION = "observation"
    VERIFICATION = "verification"
    RETEST = "retest"
    REPORT = "report"
    REVIEW = "review"
    CLOSURE = "closure"


class AssessmentCoordinatorPlan(BaseModel):
    model_config = ConfigDict(frozen=True)
    engagement_id: str
    stages: tuple[CoordinatorStage, ...] = tuple(CoordinatorStage)
    network_execution_enabled: bool = False
    fresh_permit_per_action: bool = True
    state_changing_autonomy: bool = False
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def build_coordinator_plan(engagement_id: str) -> AssessmentCoordinatorPlan:
    return AssessmentCoordinatorPlan(
        engagement_id=engagement_id,
        blockers=("operator approval remains mandatory for state-changing/intrusive actions",),
    )
