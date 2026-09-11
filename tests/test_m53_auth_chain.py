from datetime import UTC, datetime
from pathlib import Path

from astp.browser_intake import BrowserCapture
from astp.detector_execution import (
    DetectorAccounting,
    DetectorAdapterResult,
    DetectorArtifacts,
    DetectorExecutionService,
    DetectorRunStatus,
)
from astp.detector_registry import builtin_detector_registry
from astp.m53_auth_chain import derive_local_authorized_detector_request
from astp.proof_model import ProofStateV2


class RecordingAdapter:
    detector_ids = frozenset({"astp.http-observation-field.v1"})

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, _request, _permit, _run_root: Path) -> DetectorAdapterResult:
        self.calls += 1
        return DetectorAdapterResult(
            accounting=DetectorAccounting(attempted=1, forwarded=1, responses=1),
            artifacts=DetectorArtifacts(evidence_ids=("evidence-local",)),
            proof_state=ProofStateV2.OBSERVED,
            requirement_satisfied=True,
            network_started=True,
        )


def _captures(now: datetime) -> tuple[BrowserCapture, BrowserCapture]:
    detail_url = "http://local-bughunt.test/program/detail?id=local"
    listing = BrowserCapture(
        url="http://local-bughunt.test/programs",
        title="Local programs",
        text="Programas timeline\nMostrando 1 programa\nPublicado há 1 minuto",
        links=[{"text": "Local Lab", "href": detail_url}],
        captured_at=now,
    )
    detail = BrowserCapture(
        url=detail_url,
        title="Local Lab",
        text="""
Política do programa
Lista de escopo do programa
## Escopo
- http://astp-m52-lab:8080/
É proibido realizar ataques quando o programa estiver offline.
Recomendamos o User Agent: ASTP local acceptance.
""",
        captured_at=now,
    )
    return listing, detail


def test_fake_intake_derives_authorization_lease_permit_and_detector_request(tmp_path) -> None:
    now = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
    listing, detail = _captures(now)
    detector = next(
        item
        for item in builtin_detector_registry()
        if item.detector_id == "astp.http-observation-field.v1"
    )
    key = "m53-local-auth-chain-key-at-least-32-bytes"
    request, broker = derive_local_authorized_detector_request(
        root=tmp_path / "chain",
        campaign_id="m53-auth-chain",
        listing_capture=listing,
        detail_capture=detail,
        target="http://astp-m52-lab:8080/",
        detector=detector,
        runtime_digest="sha256:qualified-local-proxy",
        signing_key=key,
        now=now,
    )
    adapter = RecordingAdapter()
    result = DetectorExecutionService(tmp_path / "execution", key, (adapter,)).execute(
        request, now=now
    )

    assert result.status is DetectorRunStatus.COMPLETED
    assert result.accounting.forwarded == 1
    assert adapter.calls == 1
    assert request.execution_permit == broker.permit
    assert request.engagement.program is not None
    assert request.operational_lease is not None
    assert request.operational_lease_store_path is not None
    assert (tmp_path / "chain" / "catalog.yaml").is_file()
    assert (tmp_path / "chain" / "operational-leases.json").is_file()


def test_derived_chain_missing_permit_and_revision_drift_block_before_adapter(tmp_path) -> None:
    now = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
    listing, detail = _captures(now)
    detector = next(
        item
        for item in builtin_detector_registry()
        if item.detector_id == "astp.http-observation-field.v1"
    )
    key = "m53-local-auth-chain-key-at-least-32-bytes"
    request, _ = derive_local_authorized_detector_request(
        root=tmp_path / "chain",
        campaign_id="m53-auth-chain",
        listing_capture=listing,
        detail_capture=detail,
        target="http://astp-m52-lab:8080/",
        detector=detector,
        runtime_digest="sha256:qualified-local-proxy",
        signing_key=key,
        now=now,
    )
    adapter = RecordingAdapter()
    service = DetectorExecutionService(tmp_path / "execution", key, (adapter,))

    missing = service.execute(request.model_copy(update={"execution_permit": None}), now=now)
    stale = service.execute(
        request.model_copy(update={"current_program_revision": "changed"}), now=now
    )

    assert missing.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert stale.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert missing.authorization is stale.authorization is None
    assert adapter.calls == 0
