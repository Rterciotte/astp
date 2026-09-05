from __future__ import annotations

from pathlib import Path

import pytest

from astp.assessment_bundle import build_assessment_bundle, verify_assessment_bundle
from astp.assessment_candidate import current_autonomous_assessment_candidate
from astp.assessment_session_runner import (
    AssessmentSessionState,
    SessionDecision,
    evaluate_session_progress,
    load_session_state,
    save_session_state,
)
from astp.bounded_subprocess import BoundedProcessResult
from astp.browser_runtime import BrowserObservation
from astp.browser_runtime_supervisor import execute_browser_runtime_candidate
from astp.external_runtime_supervisor import execute_external_runtime_candidate
from astp.runtime_enablement import candidate_runtime_enablement
from astp.worker_protocol import WorkerOperation, WorkerRequest


def _request(operation: WorkerOperation, *, target: str = "https://example.com/") -> WorkerRequest:
    arguments = ()
    if operation == WorkerOperation.NMAP_DISCOVERY:
        arguments = ("tcp-connect-bounded",)
    if operation == WorkerOperation.NUCLEI_SAFE:
        arguments = ("info",)
    if operation == WorkerOperation.ZAP_BASELINE:
        arguments = ("passive-baseline",)
    return WorkerRequest(
        request_id="req-1",
        permit_id="permit-1",
        action_id="action-1",
        engagement_id="eng-1",
        operation=operation,
        target=target,
        arguments=arguments,
    )


def test_m285_runtime_candidates_are_bundled_but_not_field_qualified():
    items = candidate_runtime_enablement()
    assert len(items) == 2
    assert all(item.bundled for item in items)
    assert not any(item.field_qualified for item in items)


def test_m286_runtime_candidate_never_claims_operational_ready_early():
    assert not any(item.operational_ready for item in candidate_runtime_enablement())


def test_m287_browser_consumes_before_driver():
    calls: list[str] = []
    request = _request(WorkerOperation.BROWSER_NAVIGATE)

    def consume(_permit: str, _action: str) -> None:
        calls.append("consume")

    def driver(_request: WorkerRequest) -> BrowserObservation:
        calls.append("driver")
        return BrowserObservation(target=request.target, final_url=request.target)

    receipt = execute_browser_runtime_candidate(request, consume=consume, driver=driver)
    assert calls == ["consume", "driver"]
    assert receipt.worker_receipt.permit_consumed_before_io is True


def test_m288_browser_redirect_requires_reauthorization():
    request = _request(WorkerOperation.BROWSER_NAVIGATE)

    def driver(_request: WorkerRequest) -> BrowserObservation:
        return BrowserObservation(
            target=request.target,
            final_url="https://www.example.com/",
            redirect_observed=True,
        )

    with pytest.raises(ValueError, match="redirect requires"):
        execute_browser_runtime_candidate(request, consume=lambda *_: None, driver=driver)


def test_m289_browser_rejects_external_tool_operation():
    request = _request(WorkerOperation.NMAP_DISCOVERY, target="example.com")
    with pytest.raises(ValueError, match="bounded browser"):
        execute_browser_runtime_candidate(
            request,
            consume=lambda *_: None,
            driver=lambda _: BrowserObservation(target="example.com", final_url="example.com"),
        )


@pytest.mark.parametrize(
    "operation,target",
    [
        (WorkerOperation.NMAP_DISCOVERY, "example.com"),
        (WorkerOperation.NUCLEI_SAFE, "https://example.com/"),
        (WorkerOperation.ZAP_BASELINE, "https://example.com/"),
    ],
)
def test_m290_m292_external_candidates_consume_before_runner(operation, target):
    calls: list[str] = []
    request = _request(operation, target=target)

    def consume(_permit: str, _action: str) -> None:
        calls.append("consume")

    def runner(*_args, **_kwargs) -> BoundedProcessResult:
        calls.append("runner")
        return BoundedProcessResult(
            exit_code=0,
            stdout=b"ok",
            stderr=b"",
            output_sha256="0" * 64,
            output_truncated=False,
        )

    receipt = execute_external_runtime_candidate(request, consume=consume, runner=runner)
    assert calls == ["consume", "runner"]
    assert receipt.permit_consumed_before_io is True


def test_m293_external_candidate_rejects_browser_operation():
    request = _request(WorkerOperation.BROWSER_NAVIGATE)
    with pytest.raises(ValueError, match="allowlisted external-tool"):
        execute_external_runtime_candidate(request, consume=lambda *_: None, runner=lambda *_: None)


def test_m294_session_defaults_to_no_network_authority():
    state = AssessmentSessionState(session_id="s1", engagement_id="eng-1")
    assert state.network_execution_enabled is False
    assert state.fresh_permit_per_action is True


def test_m295_new_evidence_causes_replan():
    state = AssessmentSessionState(session_id="s1", engagement_id="eng-1")
    updated = evaluate_session_progress(state, new_evidence_ids=("ev-1",))
    assert updated.decision == SessionDecision.REPLAN


def test_m296_pending_verification_causes_replan():
    state = AssessmentSessionState(session_id="s1", engagement_id="eng-1")
    updated = evaluate_session_progress(state, new_pending_action_ids=("a-1",))
    assert updated.decision == SessionDecision.REPLAN


def test_m297_error_budget_causes_stop():
    state = AssessmentSessionState(session_id="s1", engagement_id="eng-1", errors=1)
    updated = evaluate_session_progress(state, error_budget=1)
    assert updated.decision == SessionDecision.STOP


def test_m298_action_budget_causes_stop():
    state = AssessmentSessionState(session_id="s1", engagement_id="eng-1", actions_executed=3)
    updated = evaluate_session_progress(state, action_budget=3)
    assert updated.decision == SessionDecision.STOP


def test_m299_session_state_round_trip(tmp_path: Path):
    path = tmp_path / "session.json"
    state = AssessmentSessionState(session_id="s1", engagement_id="eng-1")
    save_session_state(path, state)
    assert load_session_state(path) == state


def test_m300_bundle_is_hash_bound(tmp_path: Path):
    bundle = build_assessment_bundle(
        tmp_path,
        engagement_id="eng-1",
        report_markdown="# report\n",
        findings_payload={"findings": []},
        network_actions=2,
        permits_consumed=2,
    )
    assert bundle.assessment_complete is True
    assert verify_assessment_bundle(tmp_path)[0] is True


def test_m301_bundle_detects_tampering(tmp_path: Path):
    build_assessment_bundle(
        tmp_path,
        engagement_id="eng-1",
        report_markdown="# report\n",
        findings_payload={"findings": []},
    )
    (tmp_path / "report.md").write_text("tampered", encoding="utf-8")
    ok, blockers = verify_assessment_bundle(tmp_path)
    assert ok is False
    assert any("hash mismatch" in item for item in blockers)


def test_m302_bundle_requires_permit_count_match_for_completion(tmp_path: Path):
    bundle = build_assessment_bundle(
        tmp_path,
        engagement_id="eng-1",
        report_markdown="# report\n",
        findings_payload={"findings": []},
        network_actions=2,
        permits_consumed=1,
    )
    assert bundle.assessment_complete is False


def test_m303_candidate_does_not_claim_full_pentest_ready():
    candidate = current_autonomous_assessment_candidate()
    assert candidate.full_pentest_ready is False
    assert candidate.runtime_field_qualification_complete is False


def test_m304_candidate_names_remaining_field_blockers():
    candidate = current_autonomous_assessment_candidate()
    assert any("field-qualified" in blocker for blocker in candidate.blockers)
    assert any("end-to-end" in blocker for blocker in candidate.blockers)
