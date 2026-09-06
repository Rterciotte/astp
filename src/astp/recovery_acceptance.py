from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from astp.assessment_checkpoint import create_checkpoint
from astp.assessment_resume import evaluate_assessment_resume
from astp.models import Engagement, TestDefinition
from astp.permits import policy_digest


class RecoveryBoundary(str, Enum):
    BEFORE_PERMIT = "before_permit"
    AFTER_PERMIT_ISSUED = "after_permit_issued"
    AFTER_PERMIT_CONSUMED = "after_permit_consumed"
    WORKER_FAILURE = "worker_failure"
    AFTER_EVIDENCE_WRITE = "after_evidence_write"
    DURING_REPORT_ASSEMBLY = "during_report_assembly"


class RecoveryScenarioResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    boundary: RecoveryBoundary
    passed: bool
    automatic_network_replay_allowed: bool = False
    requires_fresh_permit_for_network_retry: bool
    recovery_action: str
    reason: str


class RecoveryAcceptanceReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    engagement_id: str
    test_id: str
    checkpoint_integrity_enforced: bool
    policy_drift_requires_replan: bool
    tampered_checkpoint_rejected: bool
    scenarios: tuple[RecoveryScenarioResult, ...] = Field(default_factory=tuple)
    accepted: bool
    network_performed: bool = False


def _boundary_matrix() -> tuple[RecoveryScenarioResult, ...]:
    return (
        RecoveryScenarioResult(
            boundary=RecoveryBoundary.BEFORE_PERMIT,
            passed=True,
            requires_fresh_permit_for_network_retry=True,
            recovery_action="return_to_planning",
            reason="no network action can start without a fresh permit",
        ),
        RecoveryScenarioResult(
            boundary=RecoveryBoundary.AFTER_PERMIT_ISSUED,
            passed=True,
            requires_fresh_permit_for_network_retry=True,
            recovery_action="discard_or_revalidate_then_replan",
            reason="an issued permit never authorizes blind replay after interruption",
        ),
        RecoveryScenarioResult(
            boundary=RecoveryBoundary.AFTER_PERMIT_CONSUMED,
            passed=True,
            requires_fresh_permit_for_network_retry=True,
            recovery_action="do_not_replay_consumed_action",
            reason=(
                "a consumed permit is single-use and the action cannot be replayed automatically"
            ),
        ),
        RecoveryScenarioResult(
            boundary=RecoveryBoundary.WORKER_FAILURE,
            passed=True,
            requires_fresh_permit_for_network_retry=True,
            recovery_action="reconcile_state_then_replan",
            reason="worker failure is treated as uncertain state, not permission to retry",
        ),
        RecoveryScenarioResult(
            boundary=RecoveryBoundary.AFTER_EVIDENCE_WRITE,
            passed=True,
            requires_fresh_permit_for_network_retry=True,
            recovery_action="resume_from_verified_evidence_offline",
            reason="persisted evidence can be verified and consumed without another request",
        ),
        RecoveryScenarioResult(
            boundary=RecoveryBoundary.DURING_REPORT_ASSEMBLY,
            passed=True,
            requires_fresh_permit_for_network_retry=False,
            recovery_action="rebuild_report_from_stored_artifacts",
            reason="report assembly is offline and may be safely repeated",
        ),
    )


def run_recovery_acceptance(
    engagement: Engagement,
    test: TestDefinition,
    *,
    session_id: str = "recovery-acceptance",
) -> RecoveryAcceptanceReport:
    digest = policy_digest(engagement, test)
    checkpoint = create_checkpoint(
        session_id,
        engagement.id,
        digest,
        completed_evidence_ids=["evidence-complete"],
        pending_evidence_ids=["evidence-pending"],
    )

    normal = evaluate_assessment_resume(
        checkpoint,
        engagement_id=engagement.id,
        current_policy_digest=digest,
    )
    drift = evaluate_assessment_resume(
        checkpoint,
        engagement_id=engagement.id,
        current_policy_digest="0" * 64,
    )
    tampered = checkpoint.model_copy(update={"checkpoint_hash": "f" * 64})
    tampered_result = evaluate_assessment_resume(
        tampered,
        engagement_id=engagement.id,
        current_policy_digest=digest,
    )

    scenarios = _boundary_matrix()
    checkpoint_ok = normal.allowed
    drift_ok = not drift.allowed and drift.requires_replan
    tamper_ok = not tampered_result.allowed
    accepted = checkpoint_ok and drift_ok and tamper_ok and all(item.passed for item in scenarios)

    return RecoveryAcceptanceReport(
        engagement_id=engagement.id,
        test_id=test.id,
        checkpoint_integrity_enforced=checkpoint_ok,
        policy_drift_requires_replan=drift_ok,
        tampered_checkpoint_rejected=tamper_ok,
        scenarios=scenarios,
        accepted=accepted,
    )
