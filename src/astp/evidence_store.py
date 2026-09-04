from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, field_validator

GENESIS_HASH = "0" * 64


class SensitivityLabel(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"


class EvidenceManifestEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    sequence: int
    evidence_id: str
    evidence_type: str
    created_at: datetime
    permit_id: str | None = None
    action_id: str | None = None
    sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL
    artifact_path: str
    artifact_sha256: str
    previous_hash: str
    entry_hash: str

    @field_validator("created_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value


@contextmanager
def _file_lock(path: Path, timeout_seconds: float = 10.0) -> Iterator[None]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    handle = None
    while handle is None:
        try:
            handle = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(handle, f"{os.getpid()}\n".encode())
        except FileExistsError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Timed out waiting for lock {lock_path}.") from None
            time.sleep(0.025)
    try:
        yield
    finally:
        os.close(handle)
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _canonical_json(data: object) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _hash_payload(data: object) -> str:
    return hashlib.sha256(_canonical_json(data)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_manifest(path: Path) -> list[EvidenceManifestEntry]:
    if not path.exists():
        return []
    entries: list[EvidenceManifestEntry] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(EvidenceManifestEntry.model_validate_json(line))
        except ValueError as exc:
            raise ValueError(f"Invalid evidence manifest record at line {line_number}.") from exc
    return entries


def register_evidence(
    manifest_path: Path,
    artifact_path: Path,
    *,
    evidence_type: str,
    evidence_id: str | None = None,
    permit_id: str | None = None,
    action_id: str | None = None,
    sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL,
    now: datetime | None = None,
) -> EvidenceManifestEntry:
    if not artifact_path.is_file():
        raise ValueError(f"Evidence artifact does not exist: {artifact_path}")
    with _file_lock(manifest_path):
        entries = _read_manifest(manifest_path)
        previous_hash = entries[-1].entry_hash if entries else GENESIS_HASH
        sequence = entries[-1].sequence + 1 if entries else 1
        created_at = now or datetime.now(UTC)
        preliminary = EvidenceManifestEntry(
            sequence=sequence,
            evidence_id=evidence_id or str(uuid4()),
            evidence_type=evidence_type,
            created_at=created_at,
            permit_id=permit_id,
            action_id=action_id,
            sensitivity=sensitivity,
            artifact_path=str(artifact_path),
            artifact_sha256=sha256_file(artifact_path),
            previous_hash=previous_hash,
            entry_hash="pending",
        )
        unsigned = preliminary.model_dump(mode="json", exclude={"entry_hash"})
        entry = preliminary.model_copy(update={"entry_hash": _hash_payload(unsigned)})
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with manifest_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry.model_dump(mode="json"), sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return entry


def verify_evidence_manifest(path: Path, *, verify_artifacts: bool = True) -> tuple[bool, str]:
    entries = _read_manifest(path)
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    for entry in entries:
        if entry.sequence != expected_sequence:
            return False, f"Unexpected sequence at evidence record {entry.sequence}."
        if entry.previous_hash != previous_hash:
            return False, f"Broken previous_hash at evidence record {entry.sequence}."
        unsigned: dict[str, Any] = entry.model_dump(mode="json", exclude={"entry_hash"})
        if _hash_payload(unsigned) != entry.entry_hash:
            return False, f"Entry hash mismatch at evidence record {entry.sequence}."
        if verify_artifacts:
            artifact = Path(entry.artifact_path)
            if not artifact.is_file():
                return False, f"Missing artifact for evidence {entry.evidence_id}."
            if sha256_file(artifact) != entry.artifact_sha256:
                return False, f"Artifact hash mismatch for evidence {entry.evidence_id}."
        previous_hash = entry.entry_hash
        expected_sequence += 1
    return True, f"Evidence manifest valid ({len(entries)} records)."
