from types import SimpleNamespace

from astp.cli import _local_bughunt_detector_requests
from astp.detector_execution import DetectorAccounting, DetectorAdapterResult, DetectorArtifacts
from astp.m53_pass1 import run_m53_pass1_execution
from astp.orchestrator_manifest import CampaignManifest, verify_campaign_manifest
from astp.orchestrator_models import AutonomousCampaignConfig
from astp.platform_adapters import LocalBughuntAdapter
from astp.proof_model import ProofStateV2


class SuccessfulAdapter:
    detector_ids = frozenset(
        {
            "nuclei.astp-lab-cve.v1",
            "ffuf.discovery-bounded.v1",
            "dalfox.reflected-bounded.v1",
        }
    )

    def execute(self, request, _permit, _run_root):
        return DetectorAdapterResult(
            accounting=DetectorAccounting(),
            artifacts=DetectorArtifacts(evidence_ids=(f"evidence-{request.program_id}",)),
            proof_state=ProofStateV2.REPRODUCED,
            requirement_satisfied=True,
        )


def test_pass1_portfolio_persists_revision_crash_retry_and_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "astp.m53_pass1.subprocess.run", lambda *args, **kwargs: SimpleNamespace(returncode=70)
    )
    campaign_id = "pass1-test"
    root = tmp_path / campaign_id
    requests = _local_bughunt_detector_requests(
        campaign_id, LocalBughuntAdapter.authenticated_fixture()
    )
    config = AutonomousCampaignConfig(
        campaign_id=campaign_id,
        selected_program_ids=tuple("ABCDEFGH"),
        dry_run=False,
        execute=True,
    )

    snapshot, results, report = run_m53_pass1_execution(
        config,
        root,
        requests=requests,
        adapter=SuccessfulAdapter(),
        signing_key="test-signing-key",
    )

    assert report.operator_interventions == 0 and report.programs_discovered == 8
    by_program = {program.program_id: program for program in report.programs}
    assert by_program["B"].detector_run_ids == ()
    assert by_program["F"].lease_ids == ("lease-2", "lease-3")
    assert by_program["G"].retries == by_program["H"].retries == 1
    assert any(result.failure_category == "lease_revoked_before_launch" for result in results)
    assert any(result.failure_category == "worker_crash" for result in results)
    assert snapshot["counters"]["permits_revoked"] == 1
    manifest = CampaignManifest.model_validate_json((root / "campaign-manifest.json").read_text())
    assert verify_campaign_manifest(manifest, root)
