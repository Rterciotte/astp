from types import SimpleNamespace

import pytest

from astp.cli import _local_bughunt_detector_requests
from astp.detector_execution import DetectorAccounting, DetectorAdapterResult, DetectorArtifacts
from astp.m53_pass1 import run_m53_pass1_execution
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


def test_legacy_pass1_executor_is_fail_closed(tmp_path, monkeypatch):
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

    with pytest.raises(RuntimeError, match="legacy pass1 execution is disabled"):
        run_m53_pass1_execution(
            config,
            root,
            requests=requests,
            adapter=SuccessfulAdapter(),
            signing_key="test-signing-key",
        )
    assert not root.exists()
