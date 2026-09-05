from datetime import UTC, datetime
from pathlib import Path

import pytest

from astp.local_qualification_lab import LocalQualificationLab
from astp.permit_consumption_proof import PermitConsumptionProof
from astp.physical_qualification_runner import _local_engagement, _qualification_test
from astp.physical_runtime_commands import compile_authorized_lab_run
from astp.runtime_resource_envelope import default_resource_envelopes
from astp.worker_protocol import WorkerOperation, WorkerRequest


def _request() -> WorkerRequest:
    return WorkerRequest(
        request_id="request-1",
        permit_id="permit-1",
        action_id="qualification-nmap-discovery",
        engagement_id="astp-local-qualification",
        operation=WorkerOperation.NMAP_DISCOVERY,
        target="astp-qualification-lab",
        arguments=("tcp-connect-bounded",),
    )


def _proof(**updates) -> PermitConsumptionProof:
    values = {
        "permit_id": "permit-1",
        "engagement_id": "astp-local-qualification",
        "test_id": "qualification-nmap-discovery",
        "target": "astp-qualification-lab",
        "action_id": "qualification-nmap-discovery",
        "consumed_at": datetime.now(UTC),
        "permit_signature_sha256": "a" * 64,
    }
    values.update(updates)
    return PermitConsumptionProof(**values)


def test_local_qualification_engagement_only_allows_lab_hostname():
    lab = LocalQualificationLab()
    engagement = _local_engagement(lab)
    assert engagement.id == lab.engagement_id
    assert engagement.scope.allowed[0].value == lab.service_name
    assert _qualification_test().risk_class.value == "safe_active"


def test_authorized_lab_compiler_requires_typed_exact_consumption_proof():
    lab = LocalQualificationLab()
    command = compile_authorized_lab_run(
        image_ref="astp/security-tools-worker:qualification",
        request_path=str(Path("C:/tmp/request.json")),
        resources=default_resource_envelopes()["security-tools.isolated.v1"],
        lab=lab,
        worker_request=_request(),
        consumption=_proof(),
    )
    joined = " ".join(command.argv)
    assert command.network_capable
    assert "--network astp-qualification-net" in joined
    assert "ASTP_ALLOWED_TARGET=astp-qualification-lab" in joined


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("permit_id", "different-permit"),
        ("engagement_id", "different-engagement"),
        ("target", "different-target"),
        ("action_id", "different-action"),
    ),
)
def test_authorized_lab_compiler_rejects_mismatched_consumption_binding(field, value):
    with pytest.raises(ValueError):
        compile_authorized_lab_run(
            image_ref="astp/security-tools-worker:qualification",
            request_path="C:/tmp/request.json",
            resources=default_resource_envelopes()["security-tools.isolated.v1"],
            lab=LocalQualificationLab(),
            worker_request=_request(),
            consumption=_proof(**{field: value}),
        )


def test_consumption_proof_has_stable_binding_hash():
    proof = _proof()
    assert proof.binding_hash() == proof.binding_hash()
    assert len(proof.binding_hash()) == 64
