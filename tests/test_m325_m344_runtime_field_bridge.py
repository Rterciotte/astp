import pytest

from astp.authorized_lab_profile import AuthorizedLabProfile, assert_lab_target
from astp.container_launch_policy import build_container_launch_plan
from astp.field_assessment_acceptance import FieldAssessmentEvidence, evaluate_field_assessment
from astp.lab_rehearsal import LabRehearsalStage, build_lab_rehearsal_plan
from astp.qualification_session import (
    QualificationProbe,
    QualificationProbeResult,
    RuntimeQualificationSession,
    evaluate_qualification_session,
)
from astp.receipt_evidence_bridge import normalize_receipt_to_evidence
from astp.runtime_image_lock import RuntimeImageLock, builtin_runtime_image_locks
from astp.worker_receipt_ingestion import WorkerReceiptEnvelope


def _lock(runtime_id="playwright.isolated.v1"):
    digest = "sha256:" + "a" * 64
    return RuntimeImageLock(
        runtime_id=runtime_id,
        image_reference=f"astp/runtime@{digest}",
        image_digest=digest,
        expected_executable="python",
        allowed_operations=("browser.observe",),
    )


def _session(*, authorized=True, omit=None):
    return RuntimeQualificationSession(
        runtime_id="playwright.isolated.v1",
        image_digest="sha256:" + "a" * 64,
        engagement_id="lab-1",
        authorized_lab=authorized,
        probes=tuple(
            QualificationProbeResult(probe=p, passed=True, evidence_ref=f"evidence:{p.value}")
            for p in QualificationProbe
            if p is not omit
        ),
    )


def _receipt(**overrides):
    values = {
        "runtime_id": "playwright.isolated.v1",
        "engagement_id": "lab-1",
        "permit_id": "permit-1",
        "action_id": "action-1",
        "artifact_digest": "sha256:" + "b" * 64,
        "permit_consumed_before_io": True,
        "network_io_performed": True,
    }
    values.update(overrides)
    return WorkerReceiptEnvelope(**values)


def test_m325_runtime_images_are_digest_pinned():
    for lock in builtin_runtime_image_locks():
        lock.validate_pinned()


def test_m326_runtime_lock_hash_is_deterministic():
    assert _lock().lock_hash() == _lock().lock_hash()


def test_m327_container_root_is_read_only():
    plan = build_container_launch_plan(_lock(), permit_consumed=False, network_requested=False)
    assert plan.policy.read_only_root is True


def test_m328_container_drops_privileged_paths():
    plan = build_container_launch_plan(_lock(), permit_consumed=False, network_requested=False)
    assert plan.policy.no_new_privileges is True
    assert plan.policy.drop_all_capabilities is True
    assert plan.policy.signing_key_mounts_allowed is False


def test_m329_shell_and_arbitrary_mounts_are_forbidden():
    plan = build_container_launch_plan(_lock(), permit_consumed=False, network_requested=False)
    assert plan.policy.shell_allowed is False
    assert plan.policy.arbitrary_mounts_allowed is False


def test_m330_network_cannot_enable_before_permit_consumption():
    plan = build_container_launch_plan(_lock(), permit_consumed=False, network_requested=True)
    assert plan.ready_for_launch is False
    assert plan.policy.network_enabled is False


def test_m331_network_plan_can_only_enable_after_consumption():
    plan = build_container_launch_plan(_lock(), permit_consumed=True, network_requested=True)
    assert plan.ready_for_launch is True
    assert plan.policy.network_enabled is True


def test_m332_qualification_session_requires_all_negative_probes():
    result = evaluate_qualification_session(_session(omit=QualificationProbe.SHELL_REJECTED))
    assert result.qualified is False
    assert "shell-rejected" in result.missing_probes


def test_m333_qualification_session_requires_authorized_lab():
    assert evaluate_qualification_session(_session(authorized=False)).qualified is False


def test_m334_qualification_session_hash_is_deterministic():
    assert _session().session_hash() == _session().session_hash()


def test_m335_complete_authorized_qualification_can_pass():
    assert evaluate_qualification_session(_session()).qualified is True


def test_m336_receipt_is_normalized_to_hash_bound_evidence():
    evidence = normalize_receipt_to_evidence(
        _receipt(), expected_engagement_id="lab-1", expected_action_id="action-1"
    )
    assert len(evidence.evidence_hash()) == 64
    assert evidence.receipt_hash


def test_m337_unconsumed_receipt_never_becomes_evidence():
    with pytest.raises(ValueError, match="provenance"):
        normalize_receipt_to_evidence(
            _receipt(permit_consumed_before_io=False),
            expected_engagement_id="lab-1",
            expected_action_id="action-1",
        )


def test_m338_cross_engagement_receipt_never_becomes_evidence():
    with pytest.raises(ValueError, match="provenance"):
        normalize_receipt_to_evidence(
            _receipt(), expected_engagement_id="lab-2", expected_action_id="action-1"
        )


def test_m339_lab_profile_requires_explicit_authorization():
    profile = AuthorizedLabProfile(
        engagement_id="lab-1", name="local", allowed_hosts=("127.0.0.1",)
    )
    with pytest.raises(ValueError, match="authorization"):
        assert_lab_target(profile, "http://127.0.0.1/")


def test_m340_lab_profile_rejects_out_of_scope_host():
    profile = AuthorizedLabProfile(
        engagement_id="lab-1",
        name="local",
        allowed_hosts=("127.0.0.1",),
        explicit_authorization=True,
    )
    with pytest.raises(ValueError, match="outside"):
        assert_lab_target(profile, "https://example.com/")


def test_m341_lab_rehearsal_covers_runtime_to_closure_cycle():
    plan = build_lab_rehearsal_plan()
    assert plan.stages == tuple(LabRehearsalStage)
    assert plan.default_network_execution_enabled is False


def test_m342_lab_rehearsal_cannot_mark_v1_ready_by_itself():
    assert build_lab_rehearsal_plan().can_mark_v1_ready is False


def test_m343_field_acceptance_remains_false_without_real_evidence():
    result = evaluate_field_assessment(FieldAssessmentEvidence())
    assert result.accepted is False
    assert result.full_pentest_ready is False


def test_m344_field_acceptance_only_closes_all_recorded_gates():
    result = evaluate_field_assessment(
        FieldAssessmentEvidence(
            authorized_lab=True,
            browser_runtime_qualified=True,
            security_tools_runtime_qualified=True,
            receipt_evidence_ingested=True,
            adaptive_replan_observed=True,
            safe_active_verifier_observed=True,
            state_change_gate_rejection_observed=True,
            report_bundle_finalized=True,
            review_completed=True,
        )
    )
    assert result.accepted is True
    assert result.full_pentest_ready is True
