from astp.active_verifier_registry import ActiveVerifierRisk, builtin_active_verifiers
from astp.assessment_execution_cycle import (
    AssessmentCycleInput,
    CycleDecision,
    evaluate_assessment_cycle,
)
from astp.end_to_end_rehearsal import RehearsalStage, build_offline_end_to_end_rehearsal
from astp.runtime_field_qualification import (
    QualificationCheck,
    RuntimeFieldAssertion,
    RuntimeFieldQualification,
    evaluate_runtime_field_qualification,
)
from astp.runtime_probe import probe_runtime_executable
from astp.v1_readiness import evaluate_v1_readiness
from astp.verification_execution_gate import (
    VerificationExecutionContext,
    evaluate_verification_execution,
)
from astp.worker_receipt_ingestion import WorkerReceiptEnvelope, evaluate_receipt_ingestion


def _qualification(*, authorized: bool = True, omit: QualificationCheck | None = None):
    assertions = tuple(
        RuntimeFieldAssertion(check=check, passed=True, evidence_ref=f"evidence:{check.value}")
        for check in QualificationCheck
        if check is not omit
    )
    return RuntimeFieldQualification(
        runtime_id="playwright.isolated.v1",
        artifact_digest="sha256:" + "a" * 64,
        test_environment="docker-linux",
        assertions=assertions,
        authorized_field_test=authorized,
    )


def _receipt(**overrides):
    values = {
        "runtime_id": "playwright.isolated.v1",
        "engagement_id": "eng-1",
        "permit_id": "permit-1",
        "action_id": "action-1",
        "artifact_digest": "sha256:" + "b" * 64,
        "permit_consumed_before_io": True,
        "network_io_performed": True,
    }
    values.update(overrides)
    return WorkerReceiptEnvelope(**values)


def test_m305_complete_runtime_field_qualification_passes():
    result = evaluate_runtime_field_qualification(_qualification())
    assert result.qualified is True
    assert result.missing_checks == ()


def test_m306_missing_negative_test_prevents_qualification():
    result = evaluate_runtime_field_qualification(
        _qualification(omit=QualificationCheck.NETWORK_WITHOUT_PERMIT_REJECTED)
    )
    assert result.qualified is False
    assert "network-without-permit-rejected" in result.missing_checks


def test_m307_authorized_field_test_is_mandatory():
    result = evaluate_runtime_field_qualification(_qualification(authorized=False))
    assert result.qualified is False
    assert any("authorized field test" in reason for reason in result.reasons)


def test_m308_qualification_hash_is_deterministic():
    first = _qualification().qualification_hash()
    second = _qualification().qualification_hash()
    assert first == second
    assert len(first) == 64


def test_m309_runtime_probe_never_claims_operational_readiness():
    probe = probe_runtime_executable("example.runtime", "definitely-not-an-astp-runtime")
    assert probe.installed is False
    assert probe.operational_ready is False
    assert probe.network_execution_performed is False


def test_m310_receipt_with_exact_binding_is_accepted():
    result = evaluate_receipt_ingestion(
        _receipt(), expected_engagement_id="eng-1", expected_action_id="action-1"
    )
    assert result.accepted is True


def test_m311_receipt_without_pre_io_permit_is_rejected():
    result = evaluate_receipt_ingestion(
        _receipt(permit_consumed_before_io=False),
        expected_engagement_id="eng-1",
        expected_action_id="action-1",
    )
    assert result.accepted is False


def test_m312_receipt_cross_engagement_is_rejected():
    result = evaluate_receipt_ingestion(
        _receipt(), expected_engagement_id="eng-2", expected_action_id="action-1"
    )
    assert result.accepted is False


def test_m313_active_verifier_catalog_contains_safe_and_state_changing_classes():
    risks = {item.risk for item in builtin_active_verifiers()}
    assert ActiveVerifierRisk.SAFE_ACTIVE in risks
    assert ActiveVerifierRisk.STATE_CHANGING in risks


def test_m314_active_verifiers_require_fresh_permits():
    assert all(item.requires_fresh_permit for item in builtin_active_verifiers())


def test_m315_safe_active_verifier_still_needs_policy_and_attestation():
    verifier = builtin_active_verifiers()[0]
    result = evaluate_verification_execution(
        verifier,
        VerificationExecutionContext(verifier_id=verifier.id, permit_id="permit-1"),
    )
    assert result.executable is False


def test_m316_state_changing_verifier_requires_operator_approval():
    verifier = next(
        item
        for item in builtin_active_verifiers()
        if item.risk is ActiveVerifierRisk.STATE_CHANGING
    )
    result = evaluate_verification_execution(
        verifier,
        VerificationExecutionContext(
            verifier_id=verifier.id,
            permit_id="permit-1",
            policy_allowed=True,
            attestation_fresh=True,
        ),
    )
    assert result.executable is False
    assert any("operator approval" in reason for reason in result.reasons)


def test_m317_policy_drift_stops_cycle():
    result = evaluate_assessment_cycle(AssessmentCycleInput(policy_drift=True))
    assert result.decision is CycleDecision.STOP


def test_m318_stale_attestation_stops_cycle():
    result = evaluate_assessment_cycle(AssessmentCycleInput(attestation_fresh=False))
    assert result.decision is CycleDecision.STOP


def test_m319_new_signal_forces_replan():
    result = evaluate_assessment_cycle(AssessmentCycleInput(new_signals=1))
    assert result.decision is CycleDecision.REPLAN
    assert result.network_execution_authorized is False


def test_m320_cycle_completion_requires_report_and_review():
    result = evaluate_assessment_cycle(
        AssessmentCycleInput(report_ready=True, review_approved=True)
    )
    assert result.decision is CycleDecision.COMPLETE


def test_m321_offline_rehearsal_covers_all_stages():
    result = build_offline_end_to_end_rehearsal()
    assert result.stages == tuple(RehearsalStage)
    assert result.network_execution_performed is False


def test_m322_offline_rehearsal_is_ready_for_authorized_field_test_not_full_readiness():
    result = build_offline_end_to_end_rehearsal()
    assert result.ready_for_authorized_field_test is True
    assert result.blockers


def test_m323_v1_readiness_remains_false_by_default():
    result = evaluate_v1_readiness()
    assert result.full_pentest_ready is False
    assert result.architecture_complete is True


def test_m324_v1_readiness_only_closes_when_all_field_gates_close():
    result = evaluate_v1_readiness(
        runtime_field_qualification_complete=True,
        broad_active_verification_field_qualified=True,
        authorized_e2e_field_test_complete=True,
    )
    assert result.full_pentest_ready is True
    assert result.blockers == ()
