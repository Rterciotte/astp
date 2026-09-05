import json
from pathlib import Path

from astp.evidence_store import verify_evidence_manifest
from astp.physical_probe_evaluator import qualification_status, record_physical_probe
from astp.qualification_session import QualificationProbe


def _root(tmp_path: Path, runtime: str = "playwright") -> Path:
    provenance = tmp_path / ".astp" / "qualification" / "images"
    provenance.mkdir(parents=True)
    (provenance / f"{runtime}.json").write_text(
        json.dumps({"image_id": "sha256:" + "a" * 64}),
        encoding="utf-8",
    )
    return tmp_path


def test_probe_source_is_copied_to_immutable_evidence(tmp_path):
    root = _root(tmp_path)
    source = tmp_path / "probe.txt"
    source.write_text("first", encoding="utf-8")
    first = record_physical_probe(
        root,
        runtime="playwright",
        probe=QualificationProbe.SHELL_REJECTED,
        passed=True,
        source_ref=source,
    )
    source.write_text("second", encoding="utf-8")
    second = record_physical_probe(
        root,
        runtime="playwright",
        probe=QualificationProbe.SIGNING_KEYS_ABSENT,
        passed=True,
        source_ref=source,
    )
    assert first.source_artifact_path != second.source_artifact_path
    assert Path(first.source_artifact_path).read_text(encoding="utf-8") == "first"
    assert Path(second.source_artifact_path).read_text(encoding="utf-8") == "second"
    assert verify_evidence_manifest(root / ".astp" / "qualification" / "evidence-manifest.jsonl")[0]


def test_qualification_status_requires_all_probes_and_valid_manifest(tmp_path):
    root = _root(tmp_path, runtime="security-tools")
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    for probe in QualificationProbe:
        record_physical_probe(
            root,
            runtime="security-tools",
            probe=probe,
            passed=True,
            authorized_lab=probe
            in {QualificationProbe.PERMIT_BEFORE_IO, QualificationProbe.RECEIPT_INGESTION},
            source_ref=source,
        )
    status = qualification_status(root, runtime="security-tools")
    assert status["qualified"] is True
    assert status["missing_probes"] == []
    assert status["manifest_valid"] is True


def test_qualification_status_fails_when_registered_artifact_is_tampered(tmp_path):
    root = _root(tmp_path, runtime="zap")
    source = tmp_path / "source.json"
    source.write_text("{}", encoding="utf-8")
    record = record_physical_probe(
        root,
        runtime="zap",
        probe=QualificationProbe.IMAGE_DIGEST,
        passed=True,
        source_ref=source,
    )
    Path(record.source_artifact_path).write_text("tampered", encoding="utf-8")
    status = qualification_status(root, runtime="zap")
    assert status["qualified"] is False
    assert status["manifest_valid"] is False
    assert any("evidence manifest invalid" in reason for reason in status["reasons"])
