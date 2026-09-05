import pytest

from astp.lifecycle import PermitLifecycleStatus
from astp.local_qualification_lab import LocalQualificationLab
from astp.permit_consumption_proof import PermitConsumptionProof
from astp.physical_probe_evaluator import PhysicalProbeEvidence, evaluate_physical_probe_evidence
from astp.physical_qualification_runner import _RUNTIME_SPECS
from astp.physical_runtime_commands import compile_authorized_lab_run
from astp.qualification_session import QualificationProbe, QualificationProbeResult
from astp.runtime_resource_envelope import default_resource_envelopes
from astp.worker_protocol import WorkerRequest


def test_all_three_physical_runtimes_have_bounded_specs():
    assert set(_RUNTIME_SPECS) == {"security-tools", "playwright", "zap"}
    assert _RUNTIME_SPECS["playwright"].operation.value == "browser.navigate"
    assert _RUNTIME_SPECS["zap"].operation.value == "external.zap.baseline"


def test_authorized_lab_command_rejects_cross_target_consumption():
    lab = LocalQualificationLab()
    spec = _RUNTIME_SPECS["playwright"]
    req = WorkerRequest(
        request_id="r",
        permit_id="p",
        action_id="a",
        engagement_id=lab.engagement_id,
        operation=spec.operation,
        target=lab.base_url() + "/health",
    )
    proof = PermitConsumptionProof(
        permit_id="p",
        engagement_id=lab.engagement_id,
        test_id="t",
        target="http://wrong:8080/health",
        action_id="a",
        consumed_at="2026-09-05T00:00:00Z",
        permit_signature_sha256="0" * 64,
        lifecycle_status=PermitLifecycleStatus.CONSUMED,
    )
    with pytest.raises(ValueError, match="target mismatch"):
        compile_authorized_lab_run(
            image_ref=spec.image_tag,
            request_path="C:/tmp/request.json",
            resources=default_resource_envelopes()[spec.runtime_id],
            lab=lab,
            worker_request=req,
            consumption=proof,
        )


def test_qualification_requires_every_physical_probe():
    probes = tuple(
        QualificationProbeResult(probe=p, passed=True, evidence_ref=f"e:{p.value}")
        for p in QualificationProbe
        if p != QualificationProbe.BOUNDED_OUTPUT
    )
    record = PhysicalProbeEvidence(
        runtime_id="playwright.isolated.v1",
        image_digest="sha256:" + "1" * 64,
        authorized_lab=True,
        probes=probes,
    )
    result = evaluate_physical_probe_evidence(record)
    assert result.qualified is False
    assert "bounded-output" in result.missing_probes


def test_complete_physical_probe_record_can_qualify():
    probes = tuple(
        QualificationProbeResult(probe=p, passed=True, evidence_ref=f"e:{p.value}")
        for p in QualificationProbe
    )
    record = PhysicalProbeEvidence(
        runtime_id="security-tools.isolated.v1",
        image_digest="sha256:" + "2" * 64,
        authorized_lab=True,
        probes=probes,
    )
    assert evaluate_physical_probe_evidence(record).qualified is True


def test_local_lab_allows_large_only_as_explicit_qualification_path():
    lab = LocalQualificationLab()
    assert lab.authorize_url(lab.base_url() + "/large").endswith("/large")
    with pytest.raises(ValueError):
        lab.authorize_url(lab.base_url() + "/arbitrary")
