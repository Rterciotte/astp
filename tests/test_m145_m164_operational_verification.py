from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from astp.adapter_evidence import summarize_adapter_receipt
from astp.approval_workflow import ApprovalDecision, record_high_risk_approval
from astp.assessment_completion import evaluate_pentest_completion
from astp.assessment_coverage import current_assessment_coverage
from astp.auth_session import AuthSessionProfile
from astp.authorization_differential import build_authorization_differential_plan
from astp.authorization_differential_executor import execute_authorization_differential
from astp.authorization_verifier import AuthorizationProofState, verify_authorization_comparison
from astp.browser_runtime import (
    BrowserObservation,
    browser_runtime_status,
    execute_browser_observation,
)
from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.capability_grant import CapabilityGrantPayload, SignedCapabilityGrant
from astp.differential_analysis import compare_authorization_evidence
from astp.evidence_store import SensitivityLabel
from astp.external_adapter_runtime import build_external_adapter_job, execute_external_adapter_job
from astp.models import RiskClass
from astp.observation import HttpObservationEvidence
from astp.pentest_readiness import current_pentest_readiness
from astp.permits import ExecutionPermitPayload, SignedExecutionPermit
from astp.retest_execution import build_retest_outcome
from astp.retest_scheduler import build_retest_request
from astp.safe_verification_executor import VerificationExecutionStatus, execute_safe_verification
from astp.state_change_gate import StateChangeGateDecision, evaluate_state_change_gate
from astp.verification_broker import VerificationAuthorizationCandidate
from astp.verification_execution import prepare_verification_execution
from astp.verification_result_repository import load_verification_result, record_verification_result

NOW = datetime(2026, 9, 5, tzinfo=UTC)


def _permit(permit_id: str, identity: str | None = None) -> SignedExecutionPermit:
    return SignedExecutionPermit(
        payload=ExecutionPermitPayload(
            permit_id=permit_id,
            key_id="local-v1",
            issuer="test",
            engagement_id="eng-1",
            test_id="test-1",
            risk_class=RiskClass.SAFE_ACTIVE,
            target="https://example.com/object/1",
            http_method="GET",
            identity=identity,
            max_requests_per_second=1,
            policy_digest="a" * 64,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
        ),
        signature="sig",
    )


def _session(identity: str) -> AuthSessionProfile:
    return AuthSessionProfile(
        id=f"session-{identity}",
        identity=identity,
        bindings=(),
        allowed_origins=("https://example.com",),
    )


def _evidence(evidence_id: str, body_hash: str = "b" * 64) -> HttpObservationEvidence:
    return HttpObservationEvidence(
        evidence_id=evidence_id,
        action_id="c" * 64,
        sensitivity=SensitivityLabel.SENSITIVE,
        permit_id=f"permit-{evidence_id}",
        engagement_id="eng-1",
        test_id="test-1",
        observed_at=NOW,
        method="GET",
        target="https://example.com/object/1",
        status_code=200,
        response_headers={"content-type": "application/json"},
        content_type="application/json",
        body_bytes_captured=12,
        body_sha256=body_hash,
        body_preview='{"id": 1}',
        evidence_hash="d" * 64,
    )


def _grant(permit: SignedExecutionPermit, action: CapabilityAction) -> SignedCapabilityGrant:
    return SignedCapabilityGrant(
        payload=CapabilityGrantPayload(
            permit_id=permit.payload.permit_id,
            key_id="local-v1",
            engagement_id="eng-1",
            test_id="test-1",
            action_id=action.action_id(),
            capability_id=action.capability_id,
            operation=action.operation.value,
            target=action.target,
            issued_at=NOW,
            expires_at=permit.payload.expires_at,
        ),
        signature="sig",
    )


def test_m145_differential_comparator_requires_same_resource():
    first = _evidence("e1")
    second = _evidence("e2").model_copy(update={"target": "https://example.com/object/2"})
    with pytest.raises(ValueError):
        compare_authorization_evidence(first, second)


def test_m146_differential_comparator_surfaces_equivalent_access_signal():
    result = compare_authorization_evidence(_evidence("e1"), _evidence("e2"))
    assert result.authorization_boundary_signal is True
    assert result.confidence >= 0.7


def test_m147_two_identity_executor_requires_fresh_permit_per_identity():
    plan = build_authorization_differential_plan("https://example.com/object/1", "alice", "bob")
    permit = _permit("permit-1")
    with pytest.raises(ValueError):
        execute_authorization_differential(
            plan,
            permit,
            permit,
            _session("alice"),
            _session("bob"),
            lambda _permit, _session: _evidence(_session.identity),
        )


def test_m148_two_identity_executor_produces_comparison():
    plan = build_authorization_differential_plan("https://example.com/object/1", "alice", "bob")
    result = execute_authorization_differential(
        plan,
        _permit("permit-a", "alice"),
        _permit("permit-b", "bob"),
        _session("alice"),
        _session("bob"),
        lambda _permit, session: _evidence(f"e-{session.identity}"),
    )
    assert result.permits_distinct is True
    assert result.comparison.authorization_boundary_signal is True


def test_m149_authorization_verifier_does_not_overclaim_without_ownership_context():
    comparison = compare_authorization_evidence(_evidence("e1"), _evidence("e2"))
    result = verify_authorization_comparison(comparison, foreign_object_confirmed=False)
    assert result.state == AuthorizationProofState.SUSPECTED
    assert result.verified_vulnerability is False


def test_m150_authorization_verifier_caps_confirmed_foreign_object_at_likely():
    comparison = compare_authorization_evidence(_evidence("e1"), _evidence("e2"))
    result = verify_authorization_comparison(comparison, foreign_object_confirmed=True)
    assert result.state == AuthorizationProofState.LIKELY
    assert result.verified_vulnerability is False


def test_m151_safe_verification_executes_only_through_dispatcher():
    candidate = VerificationAuthorizationCandidate(
        queue_item_id="queue-1", finding_id="finding-1", finding_key="authz", review_hash="a" * 64
    )
    action = CapabilityAction(
        capability_id="http.observation.v1",
        operation=CapabilityOperation.HTTP_GET,
        target="https://example.com/object/1",
    )
    envelope = prepare_verification_execution(candidate, action)
    permit = _permit("permit-v")
    grant = _grant(permit, action)
    result = execute_safe_verification(envelope, grant, permit, lambda *_: "evidence-1")
    assert result.status == VerificationExecutionStatus.COMPLETED
    assert result.evidence_id == "evidence-1"


def test_m152_verification_result_repository_is_durable(tmp_path):
    candidate = VerificationAuthorizationCandidate(
        queue_item_id="queue-1", finding_id="finding-1", finding_key="authz", review_hash="a" * 64
    )
    action = CapabilityAction(
        capability_id="http.observation.v1",
        operation=CapabilityOperation.HTTP_GET,
        target="https://example.com/object/1",
    )
    envelope = prepare_verification_execution(candidate, action)
    permit = _permit("permit-v")
    result = execute_safe_verification(envelope, _grant(permit, action), permit, lambda *_: "e-1")
    path = tmp_path / "verification.db"
    record_verification_result(path, result)
    assert load_verification_result(path, envelope.id) == result


def test_m153_retest_outcome_requires_human_resolution():
    request = build_retest_request("finding-1", now=NOW)
    candidate = VerificationAuthorizationCandidate(
        queue_item_id="queue-1", finding_id="finding-1", finding_key="authz", review_hash="a" * 64
    )
    action = CapabilityAction(
        capability_id="http.observation.v1",
        operation=CapabilityOperation.HTTP_GET,
        target="https://example.com/object/1",
    )
    envelope = prepare_verification_execution(candidate, action)
    permit = _permit("permit-v")
    verification = execute_safe_verification(
        envelope, _grant(permit, action), permit, lambda *_: "e-1"
    )
    outcome = build_retest_outcome(request, verification)
    assert outcome.completed is True
    assert outcome.resolved is None
    assert outcome.requires_human_resolution is True


def test_m154_browser_runtime_probe_never_enables_state_change():
    status = browser_runtime_status()
    assert status.state_changing_allowed is False
    assert status.arbitrary_script_allowed is False


def test_m155_browser_observation_rejects_implicit_redirect_following():
    def driver(target: str) -> BrowserObservation:
        return BrowserObservation(
            target=target,
            final_url="https://other.example/",
            redirect_observed=True,
        )

    with pytest.raises(ValueError):
        execute_browser_observation("https://example.com/", driver)


def test_m156_browser_observation_accepts_same_target_snapshot():
    result = execute_browser_observation(
        "https://example.com/",
        lambda target: BrowserObservation(target=target, final_url=target, title="Example"),
    )
    assert result.title == "Example"


def test_m157_external_adapter_job_rejects_unapproved_mode():
    with pytest.raises(ValueError):
        build_external_adapter_job(
            "nmap.safe-discovery.v1",
            "example.com",
            "syn-stealth-unbounded",
            permit_id="permit-1",
            action_id="action-1",
        )


def test_m158_external_adapter_receipt_hashes_output_instead_of_persisting_raw_data():
    job = build_external_adapter_job(
        "nmap.safe-discovery.v1",
        "example.com",
        "tcp-connect-bounded",
        permit_id="permit-1",
        action_id="action-1",
    )
    receipt = execute_external_adapter_job(job, lambda _job: (0, b"open 443", b""))
    summary = summarize_adapter_receipt(receipt)
    assert summary.successful is True
    assert summary.finding_confirmed is False
    assert "open 443" not in receipt.model_dump_json()


def test_m159_state_change_gate_allows_only_operator_controlled_execution():
    approval = record_high_risk_approval("action-1", "operator", ApprovalDecision.APPROVE, now=NOW)
    result = evaluate_state_change_gate("action-1", approval)
    assert result.decision == StateChangeGateDecision.ALLOW_OPERATOR_EXECUTION
    assert result.operator_execution_allowed is True
    assert result.autonomous_execution_allowed is False


def test_m160_state_change_gate_rejects_mismatched_action():
    approval = record_high_risk_approval("action-1", "operator", ApprovalDecision.APPROVE, now=NOW)
    result = evaluate_state_change_gate("action-2", approval)
    assert result.decision == StateChangeGateDecision.DENY


def test_m161_coverage_closes_authorization_differential_and_safe_verification():
    coverage = current_assessment_coverage()
    assert coverage.authorization_differential is True
    assert coverage.active_verification is True
    assert coverage.completed_dimensions == 9


def test_m162_readiness_closes_two_identity_executor_blocker():
    readiness = current_pentest_readiness()
    assert readiness.authorization_differential_execution is True
    assert readiness.safe_verification_execution is True
    assert readiness.full_pentest_ready is False


def test_m163_completion_remains_false_while_browser_and_tool_workers_are_incomplete():
    completion = evaluate_pentest_completion()
    assert completion.complete_end_to_end is False
    assert any("browser" in blocker for blocker in completion.blockers)


def test_m164_full_pentest_readiness_is_not_claimed_prematurely():
    readiness = current_pentest_readiness()
    assert readiness.full_pentest_ready is False
    assert readiness.browser_execution_worker is False
    assert readiness.external_tool_adapters is False
