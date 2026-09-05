from pathlib import Path

import pytest

from astp.completion_acceptance import evaluate_full_pentest_acceptance
from astp.coordinator_loop import CoordinatorLoopInput, LoopDecision, evaluate_coordinator_loop
from astp.evidence_store import verify_evidence_manifest
from astp.runtime_progress import RuntimeProgress
from astp.runtime_qualification_bundle import (
    RuntimeQualificationAssertion,
    RuntimeQualificationBundle,
    qualify_runtime_bundle,
)
from astp.runtime_specs import builtin_runtime_specs
from astp.verification_scheduler import VerificationDisposition, schedule_verification_actions
from astp.verifier_action_compiler import CompiledVerificationAction
from astp.worker_evidence_bridge import register_worker_receipt
from astp.worker_protocol import WorkerOperation, WorkerReceipt, WorkerRequest
from astp.worker_supervisor import build_worker_supervisor_plan


def _assertions(*, fail: str | None = None):
    names = (
        "permit-before-io",
        "network-without-permit-rejected",
        "shell-rejected",
        "signing-keys-absent",
        "bounded-output",
        "field-test-completed",
    )
    return tuple(
        RuntimeQualificationAssertion(
            name=name,
            passed=name != fail,
            evidence_ref=f"evidence:{name}" if name != fail else "",
        )
        for name in names
    )


def _bundle(runtime_id: str, *, fail: str | None = None):
    return RuntimeQualificationBundle(
        runtime_id=runtime_id,
        artifact_digest="sha256:" + "a" * 64,
        field_test_name="authorized-local-runtime-test",
        assertions=_assertions(fail=fail),
    )


def _request() -> WorkerRequest:
    return WorkerRequest(
        request_id="req-1",
        permit_id="permit-1",
        action_id="action-1",
        engagement_id="eng-1",
        operation=WorkerOperation.NMAP_DISCOVERY,
        target="example.com",
        arguments=("tcp-connect-bounded",),
    )


def test_m265_qualification_bundle_hash_is_stable():
    bundle = _bundle("playwright.isolated.v1")
    assert bundle.bundle_hash() == bundle.bundle_hash()
    assert len(bundle.bundle_hash()) == 64


def test_m266_runtime_binding_is_exact():
    spec = builtin_runtime_specs()[0]
    with pytest.raises(ValueError, match="runtime_id"):
        qualify_runtime_bundle(spec, _bundle("wrong.runtime"))


def test_m267_runtime_requires_digest_identity():
    spec = builtin_runtime_specs()[0]
    bundle = _bundle(spec.id).model_copy(update={"artifact_digest": "latest"})
    with pytest.raises(ValueError, match="sha256"):
        qualify_runtime_bundle(spec, bundle)


def test_m268_complete_bundle_qualifies_runtime():
    spec = builtin_runtime_specs()[0]
    record = qualify_runtime_bundle(spec, _bundle(spec.id))
    assert record.qualified is True
    assert record.field_test_name == "authorized-local-runtime-test"


def test_m269_missing_negative_check_blocks_qualification():
    spec = builtin_runtime_specs()[0]
    record = qualify_runtime_bundle(spec, _bundle(spec.id, fail="network-without-permit-rejected"))
    assert record.qualified is False
    assert record.field_test_name is None


def test_m270_supervisor_requires_consumed_permit():
    spec = builtin_runtime_specs()[1]
    plan = build_worker_supervisor_plan(
        spec, _request(), runtime_executable="worker", permit_consumed=False
    )
    assert plan.ready_for_launch is False
    assert plan.network_enabled is False
    assert any("consumed" in item for item in plan.blockers)


def test_m271_supervisor_is_shell_free_and_key_free():
    spec = builtin_runtime_specs()[1]
    plan = build_worker_supervisor_plan(
        spec, _request(), runtime_executable="worker", permit_consumed=True
    )
    assert plan.ready_for_launch is True
    assert plan.shell is False
    assert plan.signing_key_mounts == ()


def test_m272_supervisor_network_enablement_follows_consumption():
    spec = builtin_runtime_specs()[1]
    plan = build_worker_supervisor_plan(
        spec, _request(), runtime_executable="worker", permit_consumed=True
    )
    assert plan.network_enabled is True


def test_m273_worker_receipt_enters_evidence_store(tmp_path: Path):
    receipt = WorkerReceipt(
        request_id="req-1",
        permit_id="permit-1",
        action_id="action-1",
        operation=WorkerOperation.NMAP_DISCOVERY,
        exit_code=0,
        output_sha256="b" * 64,
        permit_consumed_before_io=True,
        network_io_performed=True,
    )
    registered = register_worker_receipt(
        receipt,
        manifest_path=tmp_path / "manifest.jsonl",
        artifact_directory=tmp_path / "artifacts",
    )
    assert registered.manifest_entry.permit_id == "permit-1"
    assert verify_evidence_manifest(tmp_path / "manifest.jsonl")[0] is True


def test_m274_unconsumed_receipt_is_rejected_before_evidence():
    receipt = WorkerReceipt(
        request_id="req-1",
        permit_id="permit-1",
        action_id="action-1",
        operation=WorkerOperation.NMAP_DISCOVERY,
        permit_consumed_before_io=False,
    )
    with pytest.raises(ValueError, match="permit consumption"):
        register_worker_receipt(receipt, manifest_path=Path("x"), artifact_directory=Path("y"))


def test_m275_scheduler_deduplicates_verifier_target_pairs():
    action = CompiledVerificationAction(
        id="a1", verifier_id="cors", target="https://example.com", method="GET"
    )
    other = action.model_copy(update={"id": "a2"})
    result = schedule_verification_actions((action, other))
    assert len(result) == 1


def test_m276_scheduler_marks_actions_for_policy_not_execution():
    action = CompiledVerificationAction(
        id="a1", verifier_id="cors", target="https://example.com", method="GET"
    )
    item = schedule_verification_actions((action,))[0]
    assert item.disposition is VerificationDisposition.READY_FOR_POLICY
    assert item.fresh_permit_required is True


def test_m277_scheduler_applies_action_budget():
    actions = tuple(
        CompiledVerificationAction(
            id=f"a{i}", verifier_id="cors", target=f"https://e{i}.com", method="GET"
        )
        for i in range(4)
    )
    assert len(schedule_verification_actions(actions, max_actions=2)) == 2


def test_m278_loop_replans_on_new_signals():
    result = evaluate_coordinator_loop(
        CoordinatorLoopInput(new_signals=1, action_budget_remaining=2)
    )
    assert result.decision is LoopDecision.REPLAN
    assert result.network_execution_authorized is False


def test_m279_loop_stops_on_policy_drift():
    result = evaluate_coordinator_loop(
        CoordinatorLoopInput(policy_drift=True, action_budget_remaining=2)
    )
    assert result.decision is LoopDecision.STOP


def test_m280_loop_stops_on_stale_attestation():
    result = evaluate_coordinator_loop(
        CoordinatorLoopInput(attestation_fresh=False, action_budget_remaining=2)
    )
    assert result.decision is LoopDecision.STOP


def test_m281_loop_stops_on_budget_exhaustion():
    result = evaluate_coordinator_loop(CoordinatorLoopInput(action_budget_remaining=0))
    assert result.decision is LoopDecision.STOP


def test_m282_loop_continue_still_requires_fresh_policy():
    result = evaluate_coordinator_loop(CoordinatorLoopInput(action_budget_remaining=2))
    assert result.decision is LoopDecision.CONTINUE
    assert result.requires_fresh_policy_evaluation is True


def test_m283_full_acceptance_remains_false_without_field_closure():
    progress = RuntimeProgress(qualified_runtimes=0, total_runtimes=2)
    result = evaluate_full_pentest_acceptance(
        progress,
        broad_active_verification_complete=False,
        adaptive_loop_field_tested=False,
        state_change_operator_path_field_tested=False,
        authorized_end_to_end_field_tested=False,
    )
    assert result.accepted is False
    assert len(result.blockers) == 5


def test_m284_acceptance_requires_every_gate_and_can_close_when_all_are_true():
    progress = RuntimeProgress(qualified_runtimes=2, total_runtimes=2)
    result = evaluate_full_pentest_acceptance(
        progress,
        broad_active_verification_complete=True,
        adaptive_loop_field_tested=True,
        state_change_operator_path_field_tested=True,
        authorized_end_to_end_field_tested=True,
    )
    assert result.accepted is True
    assert result.blockers == ()
