from astp.active_verifier_registry import ActiveVerifierRisk
from astp.adaptive_verification_e2e import (
    ExactApproval,
    RuntimeAdmission,
    VerificationCandidate,
    admit_qualified_runtime,
    build_verification_candidates,
    evaluate_adaptive_execution,
    extract_adaptive_signals,
    run_offline_adaptive_rehearsal,
    signals_to_hypotheses,
)
from astp.findings import ProofState


def test_m405_runtime_admission_requires_real_qualification_state() -> None:
    rejected = admit_qualified_runtime(
        RuntimeAdmission(
            runtime_id="playwright",
            image_digest="sha256:" + "1" * 64,
            manifest_valid=True,
            qualified=False,
            missing_probes=("bounded-output",),
        )
    )
    assert not rejected.admitted
    assert rejected.reasons


def test_m406_runtime_admission_accepts_digest_bound_qualified_runtime() -> None:
    accepted = admit_qualified_runtime(
        RuntimeAdmission(
            runtime_id="playwright",
            image_digest="sha256:" + "2" * 64,
            manifest_valid=True,
            qualified=True,
        )
    )
    assert accepted.admitted


def test_m407_m409_observation_signal_hypothesis_and_candidate_bridge() -> None:
    signals = extract_adaptive_signals(
        target="https://lab.invalid/account",
        evidence_id="evidence-1",
        status_code=403,
        response_headers={"Access-Control-Allow-Origin": "https://example.invalid"},
    )
    hypotheses = signals_to_hypotheses(signals)
    candidates = build_verification_candidates(hypotheses)
    assert {item.verifier_id for item in candidates} >= {
        "authorization.object-access.v2",
        "cors.controlled-origin.v1",
    }


def test_m410_m412_safe_active_requires_policy_attestation_and_fresh_permit() -> None:
    candidate = VerificationCandidate(
        id="verify-safe",
        hypothesis_id="hyp-1",
        verifier_id="cors.controlled-origin.v1",
        target="https://lab.invalid/",
        risk=ActiveVerifierRisk.SAFE_ACTIVE,
    )
    denied = evaluate_adaptive_execution(
        candidate,
        policy_allowed=True,
        attestation_fresh=True,
        permit_id=None,
    )
    assert not denied.executable
    allowed = evaluate_adaptive_execution(
        candidate,
        policy_allowed=True,
        attestation_fresh=True,
        permit_id="fresh-permit",
    )
    assert allowed.executable


def test_m420_state_change_without_exact_approval_has_zero_launch_and_io() -> None:
    candidate = VerificationCandidate(
        id="verify-state-change",
        hypothesis_id="hyp-1",
        verifier_id="session.state-change.v1",
        target="https://lab.invalid/session",
        risk=ActiveVerifierRisk.STATE_CHANGING,
        requires_exact_approval=True,
    )
    decision = evaluate_adaptive_execution(
        candidate,
        policy_allowed=True,
        attestation_fresh=True,
        permit_id="fresh-permit",
    )
    assert not decision.executable
    assert decision.zero_worker_launch
    assert decision.zero_network_io


def test_m421_exact_approval_is_action_and_target_bound() -> None:
    candidate = VerificationCandidate(
        id="verify-state-change",
        hypothesis_id="hyp-1",
        verifier_id="session.state-change.v1",
        target="https://lab.invalid/session",
        risk=ActiveVerifierRisk.STATE_CHANGING,
        requires_exact_approval=True,
    )
    wrong = ExactApproval(
        approval_id="approval-1",
        verifier_id=candidate.verifier_id,
        target="https://lab.invalid/other",
        action_id=candidate.id,
    )
    denied = evaluate_adaptive_execution(
        candidate,
        policy_allowed=True,
        attestation_fresh=True,
        permit_id="fresh-permit",
        approval=wrong,
    )
    assert not denied.executable
    exact = wrong.model_copy(update={"target": candidate.target})
    allowed = evaluate_adaptive_execution(
        candidate,
        policy_allowed=True,
        attestation_fresh=True,
        permit_id="fresh-permit-2",
        approval=exact,
    )
    assert allowed.executable
    assert not allowed.autonomous_execution_allowed


def test_m423_offline_adaptive_e2e_rehearsal() -> None:
    result = run_offline_adaptive_rehearsal()
    assert result.runtime_admitted
    assert result.signal_count >= 1
    assert result.hypothesis_count >= 1
    assert result.verification_count == 1
    assert result.proof_state is ProofState.LIKELY
    assert result.state_change_without_approval_blocked
    assert result.finding_count == 1
    assert result.report_ready
    assert result.operator_review_required
    assert not result.closure_ready
    assert len(result.trace_hash) == 64
