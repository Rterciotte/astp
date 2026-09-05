from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from astp.assessment_depth import current_assessment_depth
from astp.coordinator import CoordinatorStage
from astp.coordinator_gates import (
    CoordinatorGateContext,
    StageGateDecision,
    evaluate_stage_transition,
)
from astp.coordinator_history import list_transition_history, record_transition
from astp.evidence_store import SensitivityLabel
from astp.observation import HttpObservationEvidence, RedirectObservation
from astp.pentest_readiness import current_pentest_readiness
from astp.verification_planner import VerificationProposalStatus, propose_verification_action
from astp.verifier_catalog import builtin_verifier_catalog
from astp.verifier_depth import VerifierSignalKind, verify_stored_http_evidence
from astp.worker_runtime_manifest import builtin_worker_runtime_manifests


def _evidence(**overrides: object) -> HttpObservationEvidence:
    data: dict[str, object] = {
        "evidence_id": "ev-1",
        "action_id": "action-1",
        "permit_id": "permit-1",
        "engagement_id": "eng-1",
        "test_id": "observation.http",
        "observed_at": datetime(2026, 9, 5, tzinfo=UTC),
        "method": "GET",
        "target": "https://example.com/account",
        "status_code": 200,
        "response_headers": {},
        "body_sha256": "a" * 64,
        "evidence_hash": "b" * 64,
    }
    data.update(overrides)
    return HttpObservationEvidence(**data)


def test_m185_catalog_expands_without_confirmed_exploit_claims():
    catalog = builtin_verifier_catalog()
    ids = {item.id for item in catalog}
    assert "security-headers.csp.v1" in ids
    assert "security-headers.hsts.v1" in ids
    assert "cache.sensitive-response.v1" in ids
    assert "redirect.reauthorization.v1" in ids


def test_m186_missing_csp_is_a_posture_signal_not_confirmed_vulnerability():
    signals = verify_stored_http_evidence(_evidence())
    csp = next(item for item in signals if item.verifier_id == "security-headers.csp.v1")
    assert csp.kind is VerifierSignalKind.SECURITY_HEADER
    assert csp.confirmed_vulnerability is False


def test_m187_https_without_hsts_is_detected_from_stored_evidence():
    signals = verify_stored_http_evidence(_evidence())
    assert any(item.verifier_id == "security-headers.hsts.v1" for item in signals)


def test_m188_cors_wildcard_credentials_requires_active_verification():
    evidence = _evidence(
        response_headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    signal = next(
        item
        for item in verify_stored_http_evidence(evidence)
        if item.kind is VerifierSignalKind.CORS_POLICY
    )
    assert signal.requires_active_verification is True
    assert signal.confirmed_vulnerability is False


def test_m189_sensitive_cache_signal_is_conservative():
    evidence = _evidence(sensitivity=SensitivityLabel.SENSITIVE, response_headers={})
    signals = verify_stored_http_evidence(evidence)
    cache = next(item for item in signals if item.kind is VerifierSignalKind.CACHE_POLICY)
    assert cache.proof_ceiling == "likely"
    assert cache.confirmed_vulnerability is False


def test_m190_information_exposure_from_headers_is_not_auto_confirmed():
    evidence = _evidence(response_headers={"Server": "example-server"})
    signals = verify_stored_http_evidence(evidence)
    info = next(item for item in signals if item.kind is VerifierSignalKind.INFORMATION_EXPOSURE)
    assert info.confirmed_vulnerability is False


def test_m191_redirect_signal_preserves_new_permit_requirement():
    evidence = _evidence(
        status_code=302,
        redirect=RedirectObservation(
            target="https://www.example.com/",
            in_scope=True,
            same_origin=False,
            requires_new_permit=True,
            followed=False,
        ),
    )
    signals = verify_stored_http_evidence(evidence)
    redirect = next(item for item in signals if item.kind is VerifierSignalKind.REDIRECT_POLICY)
    assert redirect.proof_ceiling == "informational"


def test_m192_cors_signal_proposes_review_before_any_request():
    evidence = _evidence(
        response_headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    signal = next(
        item
        for item in verify_stored_http_evidence(evidence)
        if item.kind is VerifierSignalKind.CORS_POLICY
    )
    proposal = propose_verification_action(signal)
    assert proposal.status is VerificationProposalStatus.REVIEW_REQUIRED
    assert proposal.requires_fresh_permit is True
    assert proposal.state_changing is False


def test_m193_non_active_posture_signal_does_not_schedule_network():
    signal = next(
        item
        for item in verify_stored_http_evidence(_evidence())
        if item.verifier_id == "security-headers.csp.v1"
    )
    proposal = propose_verification_action(signal)
    assert proposal.status is VerificationProposalStatus.NO_ACTION
    assert proposal.action is None


def test_m194_coordinator_rejects_stage_skipping():
    result = evaluate_stage_transition(
        CoordinatorStage.INTAKE,
        CoordinatorStage.OBSERVATION,
        CoordinatorGateContext(),
    )
    assert result.decision is StageGateDecision.BLOCK


def test_m195_verification_requires_observation_evidence():
    result = evaluate_stage_transition(
        CoordinatorStage.OBSERVATION,
        CoordinatorStage.VERIFICATION,
        CoordinatorGateContext(evidence_available=False),
    )
    assert result.decision is StageGateDecision.BLOCK


def test_m196_verification_transition_allows_when_evidence_exists():
    result = evaluate_stage_transition(
        CoordinatorStage.OBSERVATION,
        CoordinatorStage.VERIFICATION,
        CoordinatorGateContext(evidence_available=True),
    )
    assert result.decision is StageGateDecision.ALLOW


def test_m197_retest_waits_for_verification_queue_to_drain():
    result = evaluate_stage_transition(
        CoordinatorStage.VERIFICATION,
        CoordinatorStage.RETEST,
        CoordinatorGateContext(verification_queue_empty=False),
    )
    assert result.decision is StageGateDecision.BLOCK


def test_m198_closure_requires_operator_review_approval():
    result = evaluate_stage_transition(
        CoordinatorStage.REVIEW,
        CoordinatorStage.CLOSURE,
        CoordinatorGateContext(review_approved=False),
    )
    assert result.decision is StageGateDecision.BLOCK


def test_m199_transition_history_is_durable(tmp_path: Path):
    db = tmp_path / "coordinator.db"
    result = evaluate_stage_transition(
        CoordinatorStage.INTAKE,
        CoordinatorStage.DISCOVERY,
        CoordinatorGateContext(),
    )
    record_transition(db, "eng-1", result)
    history = list_transition_history(db, "eng-1")
    assert len(history) == 1
    assert history[0].decision is StageGateDecision.ALLOW


def test_m200_runtime_manifests_separate_boundary_from_operational_readiness():
    manifests = builtin_worker_runtime_manifests()
    assert len(manifests) == 2
    assert all(item.permit_consumed_before_io for item in manifests)
    assert all(item.operational_ready is False for item in manifests)


def test_m201_runtime_manifests_never_expose_signing_keys_or_shell():
    manifests = builtin_worker_runtime_manifests()
    assert all(item.signing_keys_available is False for item in manifests)
    assert all(item.arbitrary_shell_allowed is False for item in manifests)


def test_m202_assessment_depth_does_not_overclaim_runtime_or_broad_active_verification():
    depth = current_assessment_depth()
    assert depth.verifier_definitions >= 10
    assert depth.operational_worker_runtimes == 0
    assert depth.broad_active_verification_ready is False
    assert depth.full_runtime_ready is False


def test_m203_pentest_readiness_remains_false_until_real_runtimes_and_depth_close():
    readiness = current_pentest_readiness()
    assert readiness.full_pentest_ready is False
    assert readiness.vulnerability_specific_active_verification is False
    assert readiness.browser_execution_worker is False
    assert readiness.external_tool_adapters is False


def test_m204_full_closure_still_requires_explicit_operator_gated_high_risk_path():
    readiness = current_pentest_readiness()
    assert readiness.state_changing_approval_workflow_execution is False
    assert any("operator-gated" in blocker for blocker in readiness.blockers)
