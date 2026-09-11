import json

import pytest
from typer.testing import CliRunner

from astp.cli import app
from astp.m53_chaos import (
    ChaosPoint,
    RecoveryClass,
    consolidate_chaos,
    inject_chaos,
    recover_chaos,
    verify_chaos_manifest,
)


def test_chaos_is_disabled_by_default(tmp_path):
    with pytest.raises(ValueError, match="disabled"):
        inject_chaos(
            tmp_path,
            "campaign",
            ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH,
            target=None,
            enabled=False,
        )


def test_chaos_cli_requires_acceptance_environment(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "orchestrator-chaos-inject",
            "--campaign-id",
            "campaign",
            "--point",
            ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF.value,
            "--root",
            str(tmp_path),
            "--acceptance-enabled",
        ],
    )
    assert result.exit_code != 0
    assert "ASTP_ACCEPTANCE_MODE=local-only" in result.output


@pytest.mark.parametrize(
    "point",
    [
        ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO,
        ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN,
        ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST,
        ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN,
    ],
)
def test_physical_chaos_cannot_use_legacy_direct_target_or_manual_accounting(tmp_path, point):
    with pytest.raises(ValueError, match="DockerDetectorAdapter lifecycle faults"):
        inject_chaos(
            tmp_path,
            "campaign",
            point,
            target="http://astp-m52-lab:8080",
            enabled=True,
        )
    assert not (tmp_path / "proxy-ledger.db").exists()


@pytest.mark.parametrize(
    ("point", "classification", "retry"),
    [
        (
            ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH,
            RecoveryClass.FAILED_BEFORE_IO,
            True,
        ),
        (
            ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF,
            RecoveryClass.RECOVERABLE_FROM_DURABLE_ARTIFACT,
            False,
        ),
        (
            ChaosPoint.AFTER_PROOF_BEFORE_FINDING,
            RecoveryClass.RECOVERABLE_FROM_DURABLE_ARTIFACT,
            False,
        ),
        (
            ChaosPoint.DURING_FINAL_REPORT_OR_MANIFEST_WRITE,
            RecoveryClass.COMPLETED,
            False,
        ),
    ],
)
def test_offline_recovery_is_idempotent(tmp_path, point, classification, retry):
    inject_chaos(tmp_path, "campaign", point, target=None, enabled=True)
    first = recover_chaos(tmp_path)
    second = recover_chaos(tmp_path)
    assert first.recovery_class is classification and first.retry is retry
    assert second.network_after_recovery == first.network_after_recovery
    assert second.duplicate_evidence == second.duplicate_findings == 0


def test_consolidated_manifest_and_required_invariants(tmp_path):
    for index, point in enumerate(ChaosPoint, 1):
        point_root = tmp_path / f"point-{index}"
        point_root.mkdir()
        payload = {
            "chaos_point": point.value,
            "recovery_class": "UNKNOWN_OUTCOME",
            "network_before_crash": 0,
            "network_after_recovery": 0,
            "retry": False,
            "fresh_permit": False,
            "unknown_outcomes": int(index == 3),
            "duplicate_evidence": 0,
            "duplicate_findings": 0,
            "orphan_workers_remaining": 0,
            "passed": True,
        }
        (point_root / "recovery-result.json").write_text(json.dumps(payload))
    report = consolidate_chaos(tmp_path, "campaign")
    assert report.chaos_points_passed == 8 and report.blind_replays == 0
    assert report.permits_reused == report.duplicate_findings == 0
    assert verify_chaos_manifest(tmp_path)
