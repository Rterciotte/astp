from typer.testing import CliRunner

from astp.cli import app
from astp.m53_full_night import FullNightReport, _hash_manifest, verify_full_night_manifest


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
