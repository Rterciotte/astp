from __future__ import annotations

import hashlib
from pathlib import Path

from astp.evidence_store import SensitivityLabel, register_evidence, verify_evidence_manifest
from astp.observation import BodyArtifactReference, _body_artifact_path, _write_body_artifact


def test_body_artifact_path_is_sibling_of_evidence() -> None:
    evidence = Path(".astp/evidence/request.json")
    assert _body_artifact_path(evidence) == Path(".astp/evidence/request.body.bin")


def test_body_artifact_persists_exact_bytes_atomically(tmp_path: Path) -> None:
    body = b"console.log('m46.7d');\n\x00\xff"
    path = tmp_path / "response.body.bin"

    _write_body_artifact(path, body)

    assert path.read_bytes() == body
    assert hashlib.sha256(path.read_bytes()).hexdigest() == hashlib.sha256(body).hexdigest()
    assert not list(tmp_path.glob(".*.tmp"))


def test_body_artifact_reference_carries_integrity_and_sensitivity(tmp_path: Path) -> None:
    body = b"bounded response"
    path = tmp_path / "response.body.bin"
    _write_body_artifact(path, body)

    reference = BodyArtifactReference(
        path=str(path),
        sha256=hashlib.sha256(body).hexdigest(),
        size_bytes=len(body),
        sensitivity=SensitivityLabel.INTERNAL,
    )

    assert reference.persisted is True
    assert reference.size_bytes == len(body)
    assert reference.sensitivity == SensitivityLabel.INTERNAL


def test_body_artifact_can_be_registered_and_verified(tmp_path: Path) -> None:
    body = b"full bounded javascript payload"
    artifact = tmp_path / "response.body.bin"
    manifest = tmp_path / "evidence-manifest.jsonl"
    _write_body_artifact(artifact, body)

    entry = register_evidence(
        manifest,
        artifact,
        evidence_type="http.observation.body",
        evidence_id="evidence-m467d",
        permit_id="permit-m467d",
        action_id="action-m467d",
        sensitivity=SensitivityLabel.INTERNAL,
    )

    assert entry.artifact_sha256 == hashlib.sha256(body).hexdigest()
    valid, message = verify_evidence_manifest(manifest)
    assert valid is True
    assert "1 records" in message
