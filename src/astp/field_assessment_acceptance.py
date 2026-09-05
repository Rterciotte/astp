from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FieldAssessmentEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)
    authorized_lab: bool = False
    browser_runtime_qualified: bool = False
    security_tools_runtime_qualified: bool = False
    receipt_evidence_ingested: bool = False
    adaptive_replan_observed: bool = False
    safe_active_verifier_observed: bool = False
    state_change_gate_rejection_observed: bool = False
    report_bundle_finalized: bool = False
    review_completed: bool = False


class FieldAssessmentAcceptance(BaseModel):
    model_config = ConfigDict(frozen=True)
    accepted: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)
    full_pentest_ready: bool = False


def evaluate_field_assessment(evidence: FieldAssessmentEvidence) -> FieldAssessmentAcceptance:
    checks = {
        "authorized lab field test is incomplete": evidence.authorized_lab,
        "browser runtime is not field-qualified": evidence.browser_runtime_qualified,
        "security-tools runtime is not field-qualified": evidence.security_tools_runtime_qualified,
        "worker receipt evidence was not ingested": evidence.receipt_evidence_ingested,
        "adaptive replan was not field-observed": evidence.adaptive_replan_observed,
        "safe active verifier was not field-observed": evidence.safe_active_verifier_observed,
        "state-changing rejection path was not field-observed": (
            evidence.state_change_gate_rejection_observed
        ),
        "report bundle was not finalized": evidence.report_bundle_finalized,
        "operator review was not completed": evidence.review_completed,
    }
    blockers = tuple(message for message, passed in checks.items() if not passed)
    return FieldAssessmentAcceptance(
        accepted=not blockers, blockers=blockers, full_pentest_ready=not blockers
    )
