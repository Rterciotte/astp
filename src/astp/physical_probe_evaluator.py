from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from astp.evidence_store import register_evidence, verify_evidence_manifest
from astp.qualification_session import (
    QualificationProbe,
    QualificationProbeResult,
    RuntimeQualificationSession,
    evaluate_qualification_session,
)


class PhysicalProbeRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    record_id: str
    runtime_id: str
    image_digest: str
    probe: QualificationProbe
    passed: bool
    authorized_lab: bool = False
    source_evidence_id: str = ""
    source_artifact_path: str = ""
    source_artifact_sha256: str = ""
    details: dict[str, object] = Field(default_factory=dict)

    def record_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


class PhysicalProbeEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    image_digest: str
    authorized_lab: bool
    probes: tuple[QualificationProbeResult, ...]

    def evidence_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


def _provenance_path(root: Path, runtime: str) -> Path:
    return root / ".astp" / "qualification" / "images" / f"{runtime}.json"


def _load_image_digest(root: Path, runtime: str) -> str:
    path = _provenance_path(root, runtime)
    if not path.is_file():
        raise FileNotFoundError(f"runtime provenance missing: {path}")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    digest = str(data.get("image_id", "")).strip()
    if not digest.startswith("sha256:") or len(digest) != 71:
        raise ValueError("runtime provenance does not contain a full image sha256")
    return digest


def _probe_dir(root: Path, runtime: str, image_digest: str) -> Path:
    return (
        root
        / ".astp"
        / "qualification"
        / "evidence"
        / "probes"
        / runtime
        / image_digest.removeprefix("sha256:")
    )


def record_physical_probe(
    root: Path,
    *,
    runtime: str,
    probe: QualificationProbe,
    passed: bool,
    authorized_lab: bool = False,
    source_ref: Path | None = None,
    details: dict[str, object] | None = None,
) -> PhysicalProbeRecord:
    image_digest = _load_image_digest(root, runtime)
    record_id = str(uuid4())
    directory = _probe_dir(root, runtime, image_digest)
    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = root / ".astp" / "qualification" / "evidence-manifest.jsonl"

    source_evidence_id = ""
    source_artifact_path = ""
    source_artifact_sha256 = ""
    if source_ref is not None:
        source = source_ref.resolve()
        if not source.is_file():
            raise FileNotFoundError(f"probe source artifact missing: {source}")
        suffix = source.suffix or ".bin"
        immutable_source = directory / f"{record_id}-source{suffix}"
        shutil.copyfile(source, immutable_source)
        source_entry = register_evidence(
            manifest_path,
            immutable_source,
            evidence_type="runtime.qualification.probe-source.v1",
        )
        source_evidence_id = source_entry.evidence_id
        source_artifact_path = source_entry.artifact_path
        source_artifact_sha256 = source_entry.artifact_sha256

    record = PhysicalProbeRecord(
        record_id=record_id,
        runtime_id=runtime,
        image_digest=image_digest,
        probe=probe,
        passed=passed,
        authorized_lab=authorized_lab,
        source_evidence_id=source_evidence_id,
        source_artifact_path=source_artifact_path,
        source_artifact_sha256=source_artifact_sha256,
        details=details or {},
    )
    record_path = directory / f"{record_id}.probe.json"
    record_path.write_text(
        json.dumps(record.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    register_evidence(
        manifest_path,
        record_path,
        evidence_type="runtime.qualification.probe.v1",
    )
    return record


def _load_probe_records(
    root: Path, runtime: str, image_digest: str
) -> tuple[PhysicalProbeRecord, ...]:
    directory = _probe_dir(root, runtime, image_digest)
    if not directory.is_dir():
        return ()
    records: list[PhysicalProbeRecord] = []
    for path in sorted(directory.glob("*.probe.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        records.append(PhysicalProbeRecord.model_validate(data))
    return tuple(records)


def build_physical_probe_evidence(root: Path, *, runtime: str) -> PhysicalProbeEvidence:
    image_digest = _load_image_digest(root, runtime)
    records = _load_probe_records(root, runtime, image_digest)
    latest: dict[QualificationProbe, PhysicalProbeRecord] = {}
    for record in records:
        latest[record.probe] = record
    probes = tuple(
        QualificationProbeResult(
            probe=probe,
            passed=record.passed,
            evidence_ref=record.record_id,
        )
        for probe, record in sorted(latest.items(), key=lambda item: item[0].value)
    )
    return PhysicalProbeEvidence(
        runtime_id=runtime,
        image_digest=image_digest,
        authorized_lab=any(record.authorized_lab and record.passed for record in records),
        probes=probes,
    )


def evaluate_physical_probe_evidence(record: PhysicalProbeEvidence):
    session = RuntimeQualificationSession(
        runtime_id=record.runtime_id,
        image_digest=record.image_digest,
        engagement_id="astp-local-qualification",
        authorized_lab=record.authorized_lab,
        probes=record.probes,
    )
    return evaluate_qualification_session(session)


def write_qualification_decision(path: Path, record: PhysicalProbeEvidence) -> None:
    decision = evaluate_physical_probe_evidence(record)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {"record_hash": record.evidence_hash(), "decision": decision.model_dump(mode="json")},
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def qualification_status(root: Path, *, runtime: str) -> dict[str, object]:
    manifest_path = root / ".astp" / "qualification" / "evidence-manifest.jsonl"
    manifest_valid, manifest_message = verify_evidence_manifest(
        manifest_path, verify_artifacts=True
    )
    record = build_physical_probe_evidence(root, runtime=runtime)
    decision = evaluate_physical_probe_evidence(record)
    qualified = bool(decision.qualified and manifest_valid)
    reasons = list(decision.reasons)
    if not manifest_valid:
        reasons.append(f"evidence manifest invalid: {manifest_message}")
    return {
        "runtime_id": runtime,
        "image_digest": record.image_digest,
        "authorized_lab": record.authorized_lab,
        "qualified": qualified,
        "missing_probes": list(decision.missing_probes),
        "reasons": reasons,
        "manifest_valid": manifest_valid,
        "manifest_message": manifest_message,
        "record_hash": record.evidence_hash(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Persist and evaluate ASTP physical runtime probes"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    record_parser = subparsers.add_parser("record")
    record_parser.add_argument("--root", type=Path, default=Path.cwd())
    record_parser.add_argument("--runtime", required=True)
    record_parser.add_argument(
        "--probe", choices=tuple(item.value for item in QualificationProbe), required=True
    )
    record_parser.add_argument("--passed", action="store_true")
    record_parser.add_argument("--authorized-lab", action="store_true")
    record_parser.add_argument("--source-ref", type=Path)
    record_parser.add_argument("--detail", action="append", default=[])

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--root", type=Path, default=Path.cwd())
    status_parser.add_argument("--runtime", required=True)

    args = parser.parse_args()
    root = args.root.resolve()
    if args.command == "record":
        details: dict[str, object] = {}
        for item in args.detail:
            if "=" not in item:
                raise SystemExit("--detail must use key=value")
            key, value = item.split("=", 1)
            details[key] = value
        record = record_physical_probe(
            root,
            runtime=args.runtime,
            probe=QualificationProbe(args.probe),
            passed=args.passed,
            authorized_lab=args.authorized_lab,
            source_ref=args.source_ref,
            details=details,
        )
        print(json.dumps(record.model_dump(mode="json"), sort_keys=True, indent=2))
        return 0

    print(json.dumps(qualification_status(root, runtime=args.runtime), sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
