import subprocess

import pytest

from astp.bounded_subprocess import BoundedProcessResult, run_bounded_subprocess
from astp.browser_protocol_worker import execute_browser_protocol_worker
from astp.browser_runtime import BrowserObservation
from astp.executable_adapter_worker import execute_tool_worker
from astp.runtime_execution_gate import evaluate_runtime_execution_gate
from astp.runtime_progress import current_runtime_progress
from astp.runtime_qualification import RuntimeQualificationEvidence, qualify_runtime
from astp.runtime_qualification_record import build_qualification_record
from astp.runtime_specs import builtin_runtime_specs
from astp.verifier_action_compiler import compile_verification_action
from astp.verifier_depth import VerifierSignal, VerifierSignalKind
from astp.worker_command import compile_worker_command
from astp.worker_protocol import WorkerOperation, WorkerReceipt, WorkerRequest
from astp.worker_receipt_evidence import receipt_to_evidence


def _tool_request(operation=WorkerOperation.NMAP_DISCOVERY, **overrides):
    values = {
        "request_id": "r1",
        "permit_id": "p1",
        "action_id": "a1",
        "engagement_id": "e1",
        "operation": operation,
        "target": "https://example.com/",
        "arguments": (),
    }
    values.update(overrides)
    return WorkerRequest(**values)


def _qualified_record(runtime_id="playwright.isolated.v1"):
    spec = next(item for item in builtin_runtime_specs() if item.id == runtime_id)
    evidence = RuntimeQualificationEvidence(
        runtime_id=runtime_id,
        artifact_digest="sha256:" + "a" * 64,
        version_reported="1",
        permit_consumed_before_io_tested=True,
        network_without_permit_rejected=True,
        arbitrary_shell_rejected=True,
        signing_keys_absent=True,
        output_bound_tested=True,
        field_test_name="authorized-lab",
    )
    result = qualify_runtime(spec, evidence)
    return build_qualification_record(
        result,
        artifact_digest=evidence.artifact_digest,
        field_test_name=evidence.field_test_name,
    )


def test_m245_nmap_command_is_bounded_and_compiled_from_mode():
    command = compile_worker_command(_tool_request())
    assert command.executable == "nmap"
    assert "--max-retries" in command.argv
    assert "example.com" in command.argv


def test_m246_nmap_service_detection_uses_light_version_probe():
    request = _tool_request(arguments=("service-detection-bounded",))
    assert "--version-light" in compile_worker_command(request).argv


def test_m247_nuclei_command_has_fixed_safe_severity():
    request = _tool_request(
        WorkerOperation.NUCLEI_SAFE,
        arguments=("low-impact",),
    )
    command = compile_worker_command(request)
    assert command.executable == "nuclei"
    assert "info,low" in command.argv


def test_m248_zap_command_is_baseline_only():
    request = _tool_request(
        WorkerOperation.ZAP_BASELINE,
        arguments=("passive-baseline",),
    )
    command = compile_worker_command(request)
    assert command.executable == "zap-baseline.py"
    assert "-t" in command.argv


def test_m249_browser_operations_are_not_compiled_as_subprocess_tools():
    request = _tool_request(WorkerOperation.BROWSER_NAVIGATE)
    with pytest.raises(ValueError, match="browser operations"):
        compile_worker_command(request)


def test_m250_bounded_subprocess_never_uses_shell():
    calls = {}

    def runner(argv, **kwargs):
        calls["argv"] = argv
        calls.update(kwargs)
        return subprocess.CompletedProcess(argv, 0, stdout=b"ok", stderr=b"")

    command = compile_worker_command(_tool_request())
    result = run_bounded_subprocess(
        command,
        timeout_seconds=5,
        max_output_bytes=1024,
        runner=runner,
    )
    assert calls["shell"] is False
    assert result.exit_code == 0


def test_m251_bounded_subprocess_truncates_oversized_output():
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, stdout=b"x" * 2000, stderr=b"")

    result = run_bounded_subprocess(
        compile_worker_command(_tool_request()),
        timeout_seconds=5,
        max_output_bytes=1024,
        runner=runner,
    )
    assert result.output_truncated is True
    assert len(result.stdout) == 1024


def test_m252_tool_worker_consumes_before_executor():
    events = []

    def consume(permit_id, action_id):
        events.append(("consume", permit_id, action_id))

    def executor(command, **kwargs):
        events.append(("execute", command.executable))
        return BoundedProcessResult(0, b"", b"", "a" * 64, False)

    receipt = execute_tool_worker(_tool_request(), consume=consume, executor=executor)
    assert events[0][0] == "consume"
    assert events[1][0] == "execute"
    assert receipt.permit_consumed_before_io is True


def test_m253_browser_worker_consumes_before_driver():
    events = []
    request = _tool_request(WorkerOperation.BROWSER_NAVIGATE)

    def consume(permit_id, action_id):
        events.append("consume")

    def driver(_request):
        events.append("driver")
        return BrowserObservation(
            target=request.target,
            final_url=request.target,
        )

    receipt = execute_browser_protocol_worker(request, consume=consume, driver=driver)
    assert events == ["consume", "driver"]
    assert receipt.permit_consumed_before_io is True


def test_m254_browser_worker_rejects_redirect_without_reauthorization():
    request = _tool_request(WorkerOperation.BROWSER_NAVIGATE)

    def driver(_request):
        return BrowserObservation(
            target=request.target,
            final_url="https://www.example.com/",
            redirect_observed=True,
        )

    with pytest.raises(ValueError, match="reauthorization"):
        execute_browser_protocol_worker(request, consume=lambda *_: None, driver=driver)


def test_m255_worker_receipt_normalizes_to_hash_bound_evidence():
    receipt = WorkerReceipt(
        request_id="r1",
        permit_id="p1",
        action_id="a1",
        operation=WorkerOperation.NMAP_DISCOVERY,
        network_io_performed=True,
        permit_consumed_before_io=True,
    )
    evidence = receipt_to_evidence(receipt)
    assert evidence.evidence_id.startswith("worker-receipt-")
    assert len(evidence.receipt_sha256) == 64


def test_m256_runtime_gate_rejects_missing_qualification_record():
    gate = evaluate_runtime_execution_gate("playwright.isolated.v1", ())
    assert gate.allowed is False


def test_m257_runtime_gate_accepts_field_qualified_record():
    gate = evaluate_runtime_execution_gate(
        "playwright.isolated.v1",
        (_qualified_record(),),
    )
    assert gate.allowed is True


def test_m258_runtime_progress_does_not_overclaim_without_records():
    progress = current_runtime_progress()
    assert progress.qualified_runtimes == 0
    assert progress.total_runtimes == 2


def test_m259_runtime_progress_can_close_one_runtime_independently():
    progress = current_runtime_progress((_qualified_record(),))
    assert progress.qualified_runtimes == 1
    assert "playwright.isolated.v1" in progress.operational_runtime_ids


def test_m260_active_verifier_signal_compiles_planning_only_action():
    signal = VerifierSignal(
        kind=VerifierSignalKind.CORS_POLICY,
        verifier_id="cors.headers.v1",
        target="https://example.com/",
        summary="candidate",
        confidence=0.9,
        requires_active_verification=True,
    )
    action = compile_verification_action(signal)
    assert action is not None
    assert action.fresh_permit_required is True
    assert action.execution_enabled is False


def test_m261_passive_signal_does_not_create_active_action():
    signal = VerifierSignal(
        kind=VerifierSignalKind.SECURITY_HEADER,
        verifier_id="security-headers.hsts.v1",
        target="https://example.com/",
        summary="missing",
        confidence=0.9,
    )
    assert compile_verification_action(signal) is None


def test_m262_tool_request_rejects_non_allowlisted_mode_before_execution():
    request = _tool_request(arguments=("-A",))
    with pytest.raises(ValueError, match="non-allowlisted"):
        compile_worker_command(request)


def test_m263_http_tool_target_must_be_absolute_url():
    request = _tool_request(WorkerOperation.NUCLEI_SAFE, target="example.com")
    with pytest.raises(ValueError, match="absolute"):
        compile_worker_command(request)


def test_m264_package_still_requires_real_field_qualification():
    progress = current_runtime_progress()
    assert progress.qualified_runtimes == 0
