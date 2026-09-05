from astp.coordinator_adaptive_loop import (
    AdaptiveLoopDecision,
    AdaptiveLoopInput,
    evaluate_adaptive_loop,
)
from astp.runtime_artifacts import RuntimeArtifact, RuntimeArtifactKind
from astp.runtime_bundle import planned_runtime_bundle
from astp.runtime_health import RuntimeHealthReport, evaluate_health
from astp.runtime_qualification_plan import build_runtime_qualification_plan
from astp.runtime_readiness_projection import project_runtime_readiness
from astp.worker_launch import WorkerLaunchDecision, WorkerLaunchEnvelope, evaluate_worker_launch
from astp.worker_protocol import (
    WorkerOperation,
    WorkerRequest,
    allowed_arguments,
    validate_worker_request,
)


def _artifact() -> RuntimeArtifact:
    return RuntimeArtifact(
        runtime_id="playwright.isolated.v1",
        kind=RuntimeArtifactKind.OCI_IMAGE,
        reference="astp/playwright-worker",
        digest="sha256:" + "a" * 64,
        version="1",
        capabilities=("browser.observation.v1",),
    )


def _envelope(artifact: RuntimeArtifact, **overrides):
    values = {
        "runtime_id": artifact.runtime_id,
        "artifact_identity_hash": artifact.identity_hash(),
        "engagement_id": "eng-1",
        "permit_id": "permit-1",
        "action_id": "action-1",
        "capability_id": "browser.observation.v1",
        "target": "https://example.com/",
    }
    values.update(overrides)
    return WorkerLaunchEnvelope(**values)


def test_m225_runtime_artifact_requires_digest_pin():
    assert _artifact().digest_is_pinned is True


def test_m226_runtime_identity_hash_is_deterministic():
    assert _artifact().identity_hash() == _artifact().identity_hash()


def test_m227_launch_envelope_accepts_exact_artifact_binding():
    artifact = _artifact()
    assert (
        evaluate_worker_launch(_envelope(artifact), artifact).decision == WorkerLaunchDecision.ALLOW
    )


def test_m228_launch_rejects_artifact_hash_drift():
    artifact = _artifact()
    result = evaluate_worker_launch(_envelope(artifact, artifact_identity_hash="bad"), artifact)
    assert result.decision == WorkerLaunchDecision.DENY


def test_m229_launch_rejects_shell():
    artifact = _artifact()
    assert (
        evaluate_worker_launch(_envelope(artifact, shell_enabled=True), artifact).decision
        == WorkerLaunchDecision.DENY
    )


def test_m230_launch_rejects_signing_key_mounts():
    artifact = _artifact()
    assert (
        evaluate_worker_launch(_envelope(artifact, signing_keys_mounted=True), artifact).decision
        == WorkerLaunchDecision.DENY
    )


def test_m231_launch_requires_read_only_rootfs():
    artifact = _artifact()
    assert (
        evaluate_worker_launch(_envelope(artifact, read_only_rootfs=False), artifact).decision
        == WorkerLaunchDecision.DENY
    )


def test_m232_browser_protocol_has_no_arbitrary_arguments():
    assert allowed_arguments(WorkerOperation.BROWSER_NAVIGATE) == ()


def test_m233_external_tool_modes_are_allowlisted():
    assert "tcp-connect-bounded" in allowed_arguments(WorkerOperation.NMAP_DISCOVERY)


def test_m234_worker_request_rejects_unlisted_argument():
    request = WorkerRequest(
        request_id="r1",
        permit_id="p1",
        action_id="a1",
        engagement_id="e1",
        operation=WorkerOperation.NMAP_DISCOVERY,
        target="example.com",
        arguments=("-A",),
    )
    assert validate_worker_request(request)


def test_m235_health_probe_must_not_use_target_network():
    report = RuntimeHealthReport(
        runtime_id="r", artifact_digest="d", version="1", healthy=True, network_test_performed=True
    )
    assert "health probe must not perform target network I/O" in evaluate_health(report)


def test_m236_health_probe_rejects_visible_signing_keys():
    report = RuntimeHealthReport(
        runtime_id="r", artifact_digest="d", version="1", healthy=True, signing_keys_visible=True
    )
    assert evaluate_health(report)


def test_m237_planned_bundle_is_not_operational_ready():
    assert planned_runtime_bundle().operational_ready is False


def test_m238_qualification_plan_includes_permit_order_test():
    plan = build_runtime_qualification_plan(planned_runtime_bundle())
    assert any(step.id == "permit-order" for step in plan.steps)


def test_m239_qualification_plan_does_not_enable_target_network():
    assert (
        build_runtime_qualification_plan(planned_runtime_bundle()).target_network_execution_enabled
        is False
    )


def test_m240_readiness_projection_does_not_overclaim():
    projection = project_runtime_readiness(planned_runtime_bundle())
    assert projection.browser_runtime_ready is False
    assert projection.external_tool_runtime_ready is False


def test_m241_adaptive_loop_stops_on_error_budget():
    result = evaluate_adaptive_loop(AdaptiveLoopInput(errors=3, max_errors=3))
    assert result.decision == AdaptiveLoopDecision.STOP


def test_m242_adaptive_loop_replans_on_new_hypothesis():
    result = evaluate_adaptive_loop(AdaptiveLoopInput(new_hypotheses=1))
    assert result.decision == AdaptiveLoopDecision.REPLAN


def test_m243_adaptive_loop_never_authorizes_network_itself():
    result = evaluate_adaptive_loop(AdaptiveLoopInput(new_hypotheses=1))
    assert result.network_execution_authorized is False


def test_m244_package_preserves_runtime_qualification_gap():
    projection = project_runtime_readiness(planned_runtime_bundle())
    assert projection.field_qualification_complete is False
