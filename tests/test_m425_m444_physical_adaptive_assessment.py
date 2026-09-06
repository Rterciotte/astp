import pytest

from astp.physical_adaptive_assessment import (
    PhysicalAdaptiveStep,
    build_physical_adaptive_trace,
    evaluate_physical_replan_gate,
    state_changing_launch_gate,
)


def step(stage: str, permit: str, evidence: str, runtime: str = "playwright.isolated.v1"):
    return PhysicalAdaptiveStep(
        stage=stage,
        runtime_id=runtime,
        permit_id=permit,
        evidence_id=evidence,
        target="http://astp-qualification-lab:8080/health",
        action_id=f"action-{permit}",
        network_execution="PERFORMED",
    )


def test_fresh_permit_allows_replan():
    gate = evaluate_physical_replan_gate(
        previous_permit_id="p1", next_permit_id="p2", policy_allowed=True, attestation_fresh=True
    )
    assert gate.decision == "continue"
    assert gate.fresh_permit is True


@pytest.mark.parametrize(
    ("policy_allowed", "attestation_fresh", "next_permit"),
    [(False, True, "p2"), (True, False, "p2"), (True, True, "p1")],
)
def test_replan_stops_on_drift_staleness_or_permit_reuse(
    policy_allowed: bool, attestation_fresh: bool, next_permit: str
):
    gate = evaluate_physical_replan_gate(
        previous_permit_id="p1",
        next_permit_id=next_permit,
        policy_allowed=policy_allowed,
        attestation_fresh=attestation_fresh,
    )
    assert gate.decision == "stop"


def test_state_change_without_exact_approval_never_launches():
    gate = state_changing_launch_gate(exact_approval=False)
    assert gate.executable is False
    assert gate.zero_worker_launch is True
    assert gate.zero_network_io is True


def test_trace_requires_fresh_permit_and_new_evidence():
    trace = build_physical_adaptive_trace(
        observation=step("observation", "p1", "e1"),
        verification=step("verification", "p2", "e2", "zap.isolated.v1"),
    )
    assert trace.replan_gate.decision == "continue"
    assert trace.finding_count == 0
    assert trace.report_ready is True
    assert trace.operator_review_required is True
    assert trace.closure_ready is False
    assert len(trace.trace_hash) == 64


def test_trace_rejects_permit_reuse():
    with pytest.raises(ValueError, match="replan gate"):
        build_physical_adaptive_trace(
            observation=step("observation", "p1", "e1"),
            verification=step("verification", "p1", "e2", "zap.isolated.v1"),
        )


def test_trace_rejects_cross_target_verification():
    verification = step("verification", "p2", "e2", "zap.isolated.v1").model_copy(
        update={"target": "http://other:8080/health"}
    )
    with pytest.raises(ValueError, match="exactly match"):
        build_physical_adaptive_trace(
            observation=step("observation", "p1", "e1"), verification=verification
        )


def test_trace_rejects_nonperformed_network():
    observation = step("observation", "p1", "e1").model_copy(
        update={"network_execution": "NOT_PERFORMED"}
    )
    with pytest.raises(ValueError, match="performed"):
        build_physical_adaptive_trace(
            observation=observation,
            verification=step("verification", "p2", "e2", "zap.isolated.v1"),
        )
