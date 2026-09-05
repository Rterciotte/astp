from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FieldReadinessInput(BaseModel):
    model_config = ConfigDict(frozen=True)
    playwright_qualified: bool = False
    security_tools_qualified: bool = False
    zap_qualified: bool = False
    adaptive_replan_observed: bool = False
    safe_active_verifier_observed: bool = False
    state_changing_rejection_observed: bool = False
    report_review_closure_observed: bool = False
    authorized_e2e_field_assessment: bool = False


class FieldReadinessDecision(BaseModel):
    model_config = ConfigDict(frozen=True)
    full_pentest_ready: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_field_readiness(value: FieldReadinessInput) -> FieldReadinessDecision:
    required = value.model_dump()
    blockers = tuple(name for name, passed in required.items() if not passed)
    return FieldReadinessDecision(full_pentest_ready=not blockers, blockers=blockers)
