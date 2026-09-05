from astp.container_launch_policy import build_container_launch_plan
from astp.docker_command_compiler import compile_build_command, compile_run_command
from astp.field_readiness import FieldReadinessInput, evaluate_field_readiness
from astp.physical_qualification import (
    PhysicalProbeObservation,
    PhysicalQualificationRecord,
    evaluate_physical_record,
)
from astp.qualification_probe_plan import physical_probe_plan
from astp.qualification_session import QualificationProbe
from astp.runtime_build_manifest import default_runtime_builds
from astp.runtime_image_lock import RuntimeImageLock


def test_default_build_manifests_are_deterministic():
    builds = default_runtime_builds()
    assert len(builds) == 3
    assert len({item.manifest_hash() for item in builds}) == 3


def test_build_command_is_shell_free_argv():
    cmd = compile_build_command(default_runtime_builds()[0], tag="astp/playwright-worker:test")
    assert cmd.argv[:2] == ("docker", "build")
    assert "--file" in cmd.argv


def test_network_run_is_blocked_before_permit():
    lock = RuntimeImageLock(
        runtime_id="r1",
        image_reference="astp/test@sha256:" + "a" * 64,
        image_digest="sha256:" + "a" * 64,
        expected_executable="python",
    )
    plan = build_container_launch_plan(lock, permit_consumed=False, network_requested=True)
    cmd = compile_run_command(plan, request_path="C:/tmp/request.json")
    assert not cmd.argv
    assert not cmd.network_capable


def test_offline_run_has_hardened_flags():
    lock = RuntimeImageLock(
        runtime_id="r1",
        image_reference="astp/test@sha256:" + "a" * 64,
        image_digest="sha256:" + "a" * 64,
        expected_executable="python",
    )
    plan = build_container_launch_plan(lock, permit_consumed=False, network_requested=False)
    cmd = compile_run_command(plan, request_path="C:/tmp/request.json")
    joined = " ".join(cmd.argv)
    assert "--read-only" in cmd.argv
    assert "no-new-privileges:true" in cmd.argv
    assert "--cap-drop" in cmd.argv
    assert "--network none" in joined


def test_physical_probe_plan_covers_all_required_probes():
    assert {step.probe for step in physical_probe_plan()} == set(QualificationProbe)


def test_partial_physical_record_cannot_qualify():
    record = PhysicalQualificationRecord(
        runtime_id="r",
        image_digest="sha256:" + "b" * 64,
        engagement_id="lab",
        authorized_lab=True,
        observations=(
            PhysicalProbeObservation(
                probe=QualificationProbe.IMAGE_DIGEST,
                passed=True,
                command_digest="c",
                output_digest="d",
            ),
        ),
    )
    assert not evaluate_physical_record(record).qualified


def test_complete_physical_record_can_qualify_only_when_authorized():
    observations = tuple(
        PhysicalProbeObservation(probe=p, passed=True, command_digest="c", output_digest=p.value)
        for p in QualificationProbe
    )
    record = PhysicalQualificationRecord(
        runtime_id="r",
        image_digest="sha256:" + "b" * 64,
        engagement_id="lab",
        authorized_lab=True,
        observations=observations,
    )
    assert evaluate_physical_record(record).qualified
    assert not evaluate_physical_record(
        record.model_copy(update={"authorized_lab": False})
    ).qualified


def test_field_readiness_defaults_false():
    result = evaluate_field_readiness(FieldReadinessInput())
    assert not result.full_pentest_ready
    assert "authorized_e2e_field_assessment" in result.blockers


def test_field_readiness_requires_every_gate():
    result = evaluate_field_readiness(
        FieldReadinessInput(
            playwright_qualified=True,
            security_tools_qualified=True,
            zap_qualified=True,
            adaptive_replan_observed=True,
            safe_active_verifier_observed=True,
            state_changing_rejection_observed=True,
            report_review_closure_observed=True,
            authorized_e2e_field_assessment=True,
        )
    )
    assert result.full_pentest_ready
