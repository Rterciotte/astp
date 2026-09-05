from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict

from astp.auth_session import AuthSessionProfile
from astp.authorization_differential import AuthorizationDifferentialPlan
from astp.differential_analysis import DifferentialComparison, compare_authorization_evidence
from astp.observation import HttpObservationEvidence
from astp.permits import SignedExecutionPermit


class DifferentialExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    plan_id: str
    baseline_identity: str
    comparison_identity: str
    baseline_evidence_id: str
    comparison_evidence_id: str
    comparison: DifferentialComparison
    permits_distinct: bool
    execution_performed: bool = True


ObservationCallable = Callable[[SignedExecutionPermit, AuthSessionProfile], HttpObservationEvidence]


def execute_authorization_differential(
    plan: AuthorizationDifferentialPlan,
    baseline_permit: SignedExecutionPermit,
    comparison_permit: SignedExecutionPermit,
    baseline_session: AuthSessionProfile,
    comparison_session: AuthSessionProfile,
    observer: ObservationCallable,
) -> DifferentialExecutionResult:
    if baseline_session.identity != plan.baseline_identity:
        raise ValueError("baseline session identity does not match differential plan")
    if comparison_session.identity != plan.comparison_identity:
        raise ValueError("comparison session identity does not match differential plan")
    if baseline_permit.payload.permit_id == comparison_permit.payload.permit_id:
        raise ValueError("authorization differential requires a fresh permit per identity")

    baseline = observer(baseline_permit, baseline_session)
    comparison = observer(comparison_permit, comparison_session)
    result = compare_authorization_evidence(baseline, comparison)
    return DifferentialExecutionResult(
        plan_id=plan.id,
        baseline_identity=plan.baseline_identity,
        comparison_identity=plan.comparison_identity,
        baseline_evidence_id=baseline.evidence_id,
        comparison_evidence_id=comparison.evidence_id,
        comparison=result,
        permits_distinct=True,
    )
