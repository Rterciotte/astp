import importlib.util
from pathlib import Path

import pytest

from astp.lifecycle import PermitLifecycleStatus
from astp.local_qualification_lab import LocalQualificationLab
from astp.permit_consumption_proof import PermitConsumptionProof
from astp.physical_runtime_commands import compile_authorized_lab_run
from astp.runtime_resource_envelope import default_resource_envelopes
from astp.worker_protocol import WorkerOperation, WorkerRequest

ROOT = Path(__file__).resolve().parents[1]


def _load_worker(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("module_name", "relative", "operation", "target"),
    [
        (
            "security_tools_qualification_worker",
            "workers/security-tools/worker.py",
            "external.nmap.discovery",
            "astp-qualification-lab",
        ),
        (
            "zap_qualification_worker",
            "workers/zap/worker.py",
            "external.zap.baseline",
            "http://astp-qualification-lab:8080/health",
        ),
    ],
)
def test_internal_bounded_output_probe_uses_real_worker_limiter(
    monkeypatch, module_name, relative, operation, target
):
    module = _load_worker(module_name, relative)
    monkeypatch.setenv("ASTP_QUALIFICATION_PROBE", "bounded-output-v1")
    result = module._qualification_bounded_output(
        {
            "operation": operation,
            "target": target,
            "max_output_bytes": 1024,
        },
        target,
    )
    assert result is not None
    assert result["output_truncated"] is True
    assert result["network_io_performed"] is False
    assert result["qualification_probe"] == "bounded-output-v1"
    assert len(result["stdout"].encode("utf-8")) == 1024


def test_authorized_lab_command_rejects_unknown_qualification_probe(tmp_path):
    lab = LocalQualificationLab()
    request = WorkerRequest(
        request_id="r1",
        permit_id="p1",
        action_id="a1",
        engagement_id=lab.engagement_id,
        operation=WorkerOperation.NMAP_DISCOVERY,
        target=lab.service_name,
        arguments=("tcp-connect-bounded",),
    )
    proof = PermitConsumptionProof(
        permit_id="p1",
        engagement_id=lab.engagement_id,
        test_id="t1",
        target=lab.service_name,
        action_id="a1",
        consumed_at="2026-09-05T00:00:00Z",
        permit_signature_sha256="a" * 64,
        lifecycle_status=PermitLifecycleStatus.CONSUMED,
    )
    with pytest.raises(ValueError, match="unsupported physical qualification probe"):
        compile_authorized_lab_run(
            image_ref="example@sha256:" + "b" * 64,
            request_path=str(tmp_path / "request.json"),
            resources=default_resource_envelopes()["security-tools.isolated.v1"],
            lab=lab,
            worker_request=request,
            consumption=proof,
            qualification_probe="not-allowed",
        )


def test_authorized_lab_command_accepts_only_exact_bounded_output_probe(tmp_path):
    lab = LocalQualificationLab()
    request = WorkerRequest(
        request_id="r2",
        permit_id="p2",
        action_id="a2",
        engagement_id=lab.engagement_id,
        operation=WorkerOperation.NMAP_DISCOVERY,
        target=lab.service_name,
        arguments=("tcp-connect-bounded",),
    )
    proof = PermitConsumptionProof(
        permit_id="p2",
        engagement_id=lab.engagement_id,
        test_id="t2",
        target=lab.service_name,
        action_id="a2",
        consumed_at="2026-09-05T00:00:00Z",
        permit_signature_sha256="c" * 64,
        lifecycle_status=PermitLifecycleStatus.CONSUMED,
    )
    command = compile_authorized_lab_run(
        image_ref="example@sha256:" + "d" * 64,
        request_path=str(tmp_path / "request.json"),
        resources=default_resource_envelopes()["security-tools.isolated.v1"],
        lab=lab,
        worker_request=request,
        consumption=proof,
        qualification_probe="bounded-output-v1",
    )
    joined = " ".join(command.argv)
    assert "ASTP_QUALIFICATION_PROBE=bounded-output-v1" in joined
    assert "ASTP_ALLOWED_TARGET=astp-qualification-lab" in joined
