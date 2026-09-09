import subprocess

from typer.testing import CliRunner

from astp.cli import _local_bughunt_detector_requests, app
from astp.detector_execution import DetectorExecutionService
from astp.docker_detector_adapter import (
    DockerDetectorAdapter,
    DockerDetectorConfig,
    DockerDetectorRuntime,
)
from astp.m53_full_night import FullNightReport, _hash_manifest, verify_full_night_manifest
from astp.platform_adapters import LocalBughuntAdapter


def _report() -> FullNightReport:
    return FullNightReport(
        campaign_id="night",
        detector_runs_started=8,
        detector_runs_completed=8,
        detector_runs_failed=1,
        permits_issued=9,
        permits_consumed=8,
        requests_attempted=10,
        requests_forwarded=9,
        responses_received=9,
        blocked_before_io=1,
        failed_after_io=0,
        finding_candidates=5,
        findings_reproduced=5,
        findings_confirmed=3,
    )


def test_full_night_readiness_keeps_autonomy_separate_from_coverage() -> None:
    report = _report()
    assert report.status == "FULL_UNATTENDED_NIGHTLY_READY"
    assert report.coverage == "DEGRADED"
    assert report.logical_duration_hours == 8
    assert report.operator_interventions == report.permits_reused == 0


def test_full_night_manifest_verifies_offline_and_detects_tampering(tmp_path) -> None:
    artifact = tmp_path / "scheduler-trace.json"
    artifact.write_text('{"rounds":4}', encoding="utf-8")
    _hash_manifest(tmp_path)
    assert verify_full_night_manifest(tmp_path)
    result = CliRunner().invoke(app, ["verify-orchestrator-campaign", str(tmp_path)])
    assert result.exit_code == 0 and "valid: YES" in result.output
    artifact.write_text('{"rounds":5}', encoding="utf-8")
    assert not verify_full_night_manifest(tmp_path)


def test_full_night_manifest_rejects_path_escape(tmp_path) -> None:
    outside = tmp_path.parent / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (tmp_path / "full-night-manifest.json").write_text(
        '{"artifacts":{"../outside.txt":"not-used"}}', encoding="utf-8"
    )
    assert not verify_full_night_manifest(tmp_path)


def test_local_physical_modes_require_explicit_acceptance_environment(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "orchestrator-start",
            "--campaign-id",
            "blocked",
            "--platform",
            "local-bughunt",
            "--all-ready",
            "--execute",
            "--docker-config",
            str(tmp_path / "missing.json"),
        ],
        env={"ASTP_DETECTOR_RUN_KEY": "x" * 32},
    )
    assert result.exit_code != 0
    assert "ASTP_ACCEPTANCE_MODE=local-only" in result.output


def test_docker_runtime_rejects_retagged_image_before_launch(tmp_path, monkeypatch) -> None:
    request = _local_bughunt_detector_requests(
        "campaign", LocalBughuntAdapter.authenticated_fixture()
    )[0]
    runtime = DockerDetectorRuntime(
        image="astp/nuclei-worker:m52", image_digest=request.runtime_digest
    )
    adapter = DockerDetectorAdapter(
        DockerDetectorConfig(
            target_network="acceptance-network",
            runtimes={request.detector.detector_id: runtime},
        ),
        "x" * 32,
    )
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "sha256:different\n", ""),
    )
    result = DetectorExecutionService(tmp_path, "x" * 32, (adapter,)).execute(request)
    assert result.failure_category == "runtime_image_identity_drift"
    assert result.accounting.forwarded == 0
