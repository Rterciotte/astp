from pathlib import Path

import pytest

from astp.local_qualification_lab import LocalQualificationLab
from astp.permit_consumption_proof import PermitConsumptionProof
from astp.physical_build_provenance import PhysicalImageIdentity, parse_repo_digest
from astp.physical_qualification_execution import (
    PhysicalExecutionObservation,
    PhysicalExecutionStage,
    PhysicalRuntimeQualificationBundle,
)
from astp.physical_runtime_commands import (
    compile_authorized_lab_run,
    compile_hardened_offline_run,
)
from astp.qualification_journal import QualificationJournalEntry, render_jsonl
from astp.qualification_session import QualificationProbe
from astp.runtime_resource_envelope import default_resource_envelopes
from astp.worker_protocol import WorkerOperation, WorkerRequest


def _identity() -> PhysicalImageIdentity:
    return PhysicalImageIdentity(
        runtime_id="security-tools.isolated.v1",
        image_tag="astp/security-tools-worker:qualification",
        image_id="sha256:" + "a" * 64,
        repo_digest=None,
        build_manifest_hash="b" * 64,
    )


def test_local_image_id_is_accepted_as_immutable_identity():
    identity = _identity()
    assert identity.immutable_digest() == identity.image_id
    assert len(identity.identity_hash()) == 64


def test_repo_digest_parser_accepts_docker_inspect_json():
    raw = '["repo@example@sha256:' + "c" * 64 + '"]'
    assert parse_repo_digest(raw) == "sha256:" + "c" * 64
    assert parse_repo_digest("[]") is None


def test_resource_envelopes_fit_small_docker_vm():
    envelopes = default_resource_envelopes()
    assert envelopes["security-tools.isolated.v1"].memory_mb == 256
    assert envelopes["playwright.isolated.v1"].memory_mb == 768
    assert envelopes["zap.isolated.v1"].memory_mb == 1024
    assert sum(item.cpus for item in envelopes.values()) > 2  # serial use is intentional


def test_offline_command_has_no_network_and_hardening_flags():
    cmd = compile_hardened_offline_run(
        image_ref="astp/security-tools-worker:qualification",
        request_path="C:/tmp/request.json",
        resources=default_resource_envelopes()["security-tools.isolated.v1"],
    )
    joined = " ".join(cmd.argv)
    assert "--network none" in joined
    assert "--read-only" in cmd.argv
    assert "no-new-privileges:true" in cmd.argv
    assert "--cap-drop" in cmd.argv
    assert not cmd.network_capable


def _lab_worker_request():
    return WorkerRequest(
        request_id="request-1",
        permit_id="permit-1",
        action_id="action-1",
        engagement_id="astp-local-qualification",
        operation=WorkerOperation.NMAP_DISCOVERY,
        target="astp-qualification-lab",
        arguments=("tcp-connect-bounded",),
    )


def _lab_consumption():
    from datetime import UTC, datetime

    return PermitConsumptionProof(
        permit_id="permit-1",
        engagement_id="astp-local-qualification",
        test_id="qualification-nmap-discovery",
        target="astp-qualification-lab",
        action_id="action-1",
        consumed_at=datetime.now(UTC),
        permit_signature_sha256="a" * 64,
    )


def test_lab_command_uses_only_fixed_internal_network_after_consumption_proof():
    lab = LocalQualificationLab()
    cmd = compile_authorized_lab_run(
        image_ref="astp/security-tools-worker:qualification",
        request_path="C:/tmp/request.json",
        resources=default_resource_envelopes()["security-tools.isolated.v1"],
        lab=lab,
        worker_request=_lab_worker_request(),
        consumption=_lab_consumption(),
    )
    joined = " ".join(cmd.argv)
    assert f"--network {lab.docker_network}" in joined
    assert f"ASTP_ALLOWED_TARGET={lab.service_name}" in joined
    assert cmd.network_capable


def test_lab_url_is_strictly_contained():
    lab = LocalQualificationLab()
    assert lab.authorize_url(lab.base_url() + "/health").endswith("/health")
    with pytest.raises(ValueError):
        lab.authorize_url("https://example.com/")
    with pytest.raises(ValueError):
        lab.authorize_url(lab.base_url() + "/admin")


def test_bundle_only_qualifies_with_every_probe_and_authorized_lab():
    observations = tuple(
        PhysicalExecutionObservation(
            probe=probe,
            passed=True,
            stage=PhysicalExecutionStage.AUTHORIZED_LAB,
            evidence_path=f"evidence/{probe.value}.json",
            command_digest="c" * 64,
            output_digest="d" * 64,
        )
        for probe in QualificationProbe
    )
    bundle = PhysicalRuntimeQualificationBundle(
        identity=_identity(),
        engagement_id="astp-local-qualification",
        authorized_lab=True,
        observations=observations,
    )
    assert bundle.qualified()
    assert bundle.missing_probes() == ()
    assert not bundle.model_copy(update={"authorized_lab": False}).qualified()


def test_partial_bundle_never_self_certifies():
    bundle = PhysicalRuntimeQualificationBundle(
        identity=_identity(), engagement_id="astp-local-qualification", authorized_lab=True
    )
    assert not bundle.qualified()
    assert set(bundle.missing_probes()) == {item.value for item in QualificationProbe}


def test_qualification_journal_is_hashable_jsonl():
    entry = QualificationJournalEntry(
        runtime_id="security-tools.isolated.v1",
        stage="build",
        event="image-built",
        evidence_path=".astp/qualification/images/security-tools.json",
    )
    assert len(entry.entry_hash()) == 64
    assert '"event":"image-built"' in render_jsonl((entry,))


def test_worker_sources_do_not_use_shell_true():
    root = Path(__file__).resolve().parents[1]
    for rel in (
        "workers/security-tools/worker.py",
        "workers/playwright/worker.py",
        "workers/zap/worker.py",
    ):
        source = (root / rel).read_text(encoding="utf-8")
        assert "shell=True" not in source
        assert "ASTP_ALLOWED_TARGET" in source
