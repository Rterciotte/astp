import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from astp.cli import _local_bughunt_detector_requests, app
from astp.detector_execution import DetectorExecutionService
from astp.docker_detector_adapter import (
    DockerDetectorAdapter,
    DockerDetectorConfig,
    DockerDetectorRuntime,
)
from astp.m53_full_night import (
    FullNightReport,
    _hash_manifest,
    _real_lease_lifecycle,
    _verify_scheduler_execution_trace,
    verify_full_night_manifest,
)
from astp.platform_adapters import LocalBughuntAdapter


def _report() -> FullNightReport:
    return FullNightReport(
        campaign_id="night",
        logical_duration_hours=8,
        scheduler_rounds=4,
        program_refreshes=2,
        programs_discovered=8,
        programs_processed=8,
        detector_runs_started=8,
        detector_runs_completed=8,
        detector_runs_failed=1,
        lease_renewals=1,
        leases_issued=9,
        leases_expired=5,
        leases_invalidated=1,
        revision_replans=1,
        runtime_retries=2,
        backoffs_429=1,
        process_restarts=1,
        recovery_events=3,
        branches_exhausted=1,
        permits_issued=9,
        permits_consumed=8,
        permits_expired=0,
        permits_revoked=1,
        requests_attempted=10,
        requests_forwarded=9,
        responses_received=9,
        blocked_before_io=1,
        failed_after_io=0,
        finding_candidates=5,
        findings_reproduced=5,
        findings_confirmed=3,
        deadline_drain="COMPLETED",
        policy_events=("program.ready", "revision.replanned"),
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


def test_full_night_lease_counts_are_derived_from_real_durable_lifecycle(tmp_path) -> None:
    trace = _real_lease_lifecycle(tmp_path, datetime(2026, 1, 1, tzinfo=UTC))
    assert trace["issued"] == 11
    assert trace["renewed"] == trace["expired"] == trace["invalidated"] == 1
    assert len(trace["lease_ids"]["F"]) == 2


def test_trace_oracle_rejects_hidden_retry_or_reused_permit() -> None:
    trace = {
        "events": [
            {
                "event": "attempt.finished",
                "program_id": "H",
                "work_id": "H-1",
                "run_id": "run-1",
                "permit_id": "permit-1",
                "round": 1,
                "retry_after_seconds": 2,
            },
            {"event": "work.completed", "work_id": "H-1"},
            {
                "event": "attempt.finished",
                "program_id": "H",
                "work_id": "H-2",
                "run_id": "run-2",
                "permit_id": "permit-2",
                "round": 2,
                "retry_after_seconds": None,
            },
            {"event": "work.completed", "work_id": "H-2"},
        ]
    }
    results = (
        SimpleNamespace(detector_run_id="run-1", target="http://astp-m52-lab:8080/"),
        SimpleNamespace(detector_run_id="run-2", target="http://astp-m52-lab:8080/"),
    )
    _verify_scheduler_execution_trace(trace, results)
    trace["events"][2]["permit_id"] = "permit-1"
    with pytest.raises(RuntimeError, match="reused"):
        _verify_scheduler_execution_trace(trace, results)


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
            "--root",
            str(tmp_path / "campaigns"),
            "--execute",
            "--docker-config",
            str(tmp_path / "missing.json"),
        ],
        env={"ASTP_DETECTOR_RUN_KEY": "x" * 32},
    )
    assert result.exit_code != 0
    assert "ASTP_ACCEPTANCE_MODE=local-only" in result.output


def test_local_physical_mode_rejects_legacy_pass1_execution_path(tmp_path) -> None:
    result = CliRunner().invoke(
        app,
        [
            "orchestrator-start",
            "--campaign-id",
            "blocked-legacy",
            "--platform",
            "local-bughunt",
            "--all-ready",
            "--execute",
            "--docker-config",
            str(tmp_path / "unused.json"),
        ],
        env={
            "ASTP_ACCEPTANCE_MODE": "local-only",
            "ASTP_DETECTOR_RUN_KEY": "x" * 32,
        },
    )
    assert result.exit_code != 0
    assert not (tmp_path / "campaigns" / "blocked-legacy").exists()


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
            proxy_image_digest="sha256:proxy",
            runtimes={request.detector.detector_id: runtime},
        ),
        "x" * 32,
    )
    monkeypatch.setattr(
        adapter,
        "_run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv,
            0,
            "sha256:proxy\n" if argv[-1] == "astp/counting-proxy:m52" else "sha256:different\n",
            "",
        ),
    )
    result = DetectorExecutionService(tmp_path, "x" * 32, (adapter,)).execute(request)
    assert result.failure_category == "runtime_image_identity_drift"
    assert result.accounting.forwarded == 0


def test_docker_runtime_rejects_retagged_proxy_before_detector_inspection(
    tmp_path, monkeypatch
) -> None:
    request = _local_bughunt_detector_requests(
        "campaign", LocalBughuntAdapter.authenticated_fixture()
    )[0]
    runtime = DockerDetectorRuntime(
        image="astp/nuclei-worker:m52", image_digest=request.runtime_digest
    )
    adapter = DockerDetectorAdapter(
        DockerDetectorConfig(
            target_network="acceptance-network",
            proxy_image_digest="sha256:expected-proxy",
            runtimes={request.detector.detector_id: runtime},
        ),
        "x" * 32,
    )
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "sha256:different-proxy\n", "")

    monkeypatch.setattr(adapter, "_run", fake_run)
    result = DetectorExecutionService(tmp_path, "x" * 32, (adapter,)).execute(request)
    assert result.failure_category == "proxy_image_identity_drift"
    assert result.accounting.forwarded == 0
    assert calls == [
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            "astp/counting-proxy:m52",
        ]
    ]
