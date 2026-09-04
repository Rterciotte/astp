from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, field_validator

from astp.evidence_store import EvidenceManifestEntry, verify_evidence_manifest


class BundleArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: str
    evidence_type: str
    path: str
    sha256: str


class EvidenceBundleReceipt(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    bundle_id: str
    created_at: datetime
    source_manifest_sha256: str
    artifacts: tuple[BundleArtifact, ...]
    receipt_hash: str

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _hash_payload(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _manifest_entries(path: Path) -> list[EvidenceManifestEntry]:
    entries: list[EvidenceManifestEntry] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(EvidenceManifestEntry.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid evidence manifest record at line {line_number}.") from exc
    return entries


def _bundle_artifact_path(entry: EvidenceManifestEntry, artifact: Path) -> str:
    safe_name = artifact.name.replace("/", "_").replace("\\", "_")
    return f"artifacts/{entry.sequence:06d}-{entry.evidence_id}-{safe_name}"


def export_evidence_bundle(
    manifest_path: Path,
    bundle_path: Path,
    *,
    now: datetime | None = None,
) -> EvidenceBundleReceipt:
    valid, message = verify_evidence_manifest(manifest_path, verify_artifacts=True)
    if not valid:
        raise ValueError(f"Cannot export invalid evidence manifest: {message}")

    entries = _manifest_entries(manifest_path)
    artifacts: list[BundleArtifact] = []
    source_manifest = manifest_path.read_bytes()

    for entry in entries:
        artifact = Path(entry.artifact_path)
        bundled_path = _bundle_artifact_path(entry, artifact)
        artifacts.append(
            BundleArtifact(
                evidence_id=entry.evidence_id,
                evidence_type=entry.evidence_type,
                path=bundled_path,
                sha256=entry.artifact_sha256,
            )
        )

    preliminary = EvidenceBundleReceipt(
        bundle_id=str(uuid4()),
        created_at=now or datetime.now(UTC),
        source_manifest_sha256=hashlib.sha256(source_manifest).hexdigest(),
        artifacts=tuple(artifacts),
        receipt_hash="pending",
    )
    unsigned = preliminary.model_dump(mode="json", exclude={"receipt_hash"})
    receipt = preliminary.model_copy(update={"receipt_hash": _hash_payload(unsigned)})

    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.jsonl", source_manifest)
        archive.writestr(
            "receipt.json",
            json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        )
        for entry, artifact_record in zip(entries, artifacts, strict=True):
            archive.write(Path(entry.artifact_path), artifact_record.path)
    return receipt


def _safe_bundle_member(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def verify_evidence_bundle(bundle_path: Path) -> tuple[bool, str]:
    if not bundle_path.is_file():
        return False, "Evidence bundle does not exist."
    try:
        with zipfile.ZipFile(bundle_path, "r") as archive:
            names = set(archive.namelist())
            if "receipt.json" not in names or "manifest.jsonl" not in names:
                return False, "Evidence bundle is missing receipt.json or manifest.jsonl."
            if any(not _safe_bundle_member(name) for name in names):
                return False, "Evidence bundle contains an unsafe member path."
            receipt = EvidenceBundleReceipt.model_validate_json(archive.read("receipt.json"))
            unsigned = receipt.model_dump(mode="json", exclude={"receipt_hash"})
            if _hash_payload(unsigned) != receipt.receipt_hash:
                return False, "Evidence bundle receipt hash mismatch."
            manifest_bytes = archive.read("manifest.jsonl")
            if hashlib.sha256(manifest_bytes).hexdigest() != receipt.source_manifest_sha256:
                return False, "Evidence bundle manifest hash mismatch."
            for artifact in receipt.artifacts:
                if artifact.path not in names:
                    return False, f"Missing bundled artifact for evidence {artifact.evidence_id}."
                if hashlib.sha256(archive.read(artifact.path)).hexdigest() != artifact.sha256:
                    return False, f"Bundled artifact hash mismatch for {artifact.evidence_id}."
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        return False, f"Invalid evidence bundle: {exc}"
    return True, f"Evidence bundle valid ({len(receipt.artifacts)} artifacts)."
