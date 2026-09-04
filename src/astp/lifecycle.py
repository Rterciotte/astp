from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from pydantic import BaseModel, Field

from astp.models import Engagement, TestDefinition
from astp.permits import (
    PermitVerificationRequest,
    PermitVerificationResult,
    SignedExecutionPermit,
    verify_execution_permit,
)

STATE_SCHEMA_VERSION = 1
AUDIT_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64


class PermitLifecycleStatus(str, Enum):
    AVAILABLE = "available"
    CONSUMED = "consumed"
    REVOKED = "revoked"


class PermitStateEntry(BaseModel):
    status: PermitLifecycleStatus
    updated_at: datetime
    reason: str | None = None


class PermitState(BaseModel):
    schema_version: int = STATE_SCHEMA_VERSION
    permits: dict[str, PermitStateEntry] = Field(default_factory=dict)


class AuditRecord(BaseModel):
    schema_version: int = AUDIT_SCHEMA_VERSION
    sequence: int
    timestamp: datetime
    event: str
    permit_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str
    record_hash: str


class ConsumeResult(BaseModel):
    accepted: bool
    verification: PermitVerificationResult
    lifecycle_status: PermitLifecycleStatus
    message: str


def _canonical_json(data: object) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _load_state(path: Path) -> PermitState:
    if not path.exists():
        return PermitState()
    data = json.loads(path.read_text(encoding="utf-8"))
    return PermitState.model_validate(data)


def _write_state(path: Path, state: PermitState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    rendered = json.dumps(state.model_dump(mode="json"), indent=2, sort_keys=True)
    temporary.write_text(rendered + "\n", encoding="utf-8")
    os.replace(temporary, path)


def permit_status(path: Path, permit_id: str) -> PermitLifecycleStatus:
    entry = _load_state(path).permits.get(permit_id)
    return entry.status if entry else PermitLifecycleStatus.AVAILABLE


def revoke_permit(
    state_path: Path,
    permit_id: str,
    *,
    reason: str,
    now: datetime | None = None,
) -> PermitStateEntry:
    current = now or datetime.now(timezone.utc)
    state = _load_state(state_path)
    existing = state.permits.get(permit_id)
    if existing and existing.status == PermitLifecycleStatus.CONSUMED:
        raise ValueError("a consumed permit cannot be retroactively revoked")
    entry = PermitStateEntry(
        status=PermitLifecycleStatus.REVOKED,
        updated_at=current,
        reason=reason,
    )
    state.permits[permit_id] = entry
    _write_state(state_path, state)
    return entry


def _consume_state(
    state_path: Path,
    permit_id: str,
    *,
    now: datetime,
) -> PermitStateEntry:
    state = _load_state(state_path)
    existing = state.permits.get(permit_id)
    if existing is not None:
        if existing.status == PermitLifecycleStatus.REVOKED:
            raise ValueError("permit has been revoked")
        if existing.status == PermitLifecycleStatus.CONSUMED:
            raise ValueError("permit has already been consumed")
    entry = PermitStateEntry(
        status=PermitLifecycleStatus.CONSUMED,
        updated_at=now,
    )
    state.permits[permit_id] = entry
    _write_state(state_path, state)
    return entry


def consume_execution_permit(
    permit: SignedExecutionPermit,
    engagement: Engagement,
    test: TestDefinition,
    request: PermitVerificationRequest,
    keys: str | bytes | Mapping[str, str | bytes],
    state_path: Path,
) -> ConsumeResult:
    status = permit_status(state_path, permit.payload.permit_id)
    if status == PermitLifecycleStatus.REVOKED:
        return ConsumeResult(
            accepted=False,
            verification=PermitVerificationResult(valid=False),
            lifecycle_status=status,
            message="Permit has been revoked.",
        )
    if status == PermitLifecycleStatus.CONSUMED:
        return ConsumeResult(
            accepted=False,
            verification=PermitVerificationResult(valid=False),
            lifecycle_status=status,
            message="Permit has already been consumed; replay rejected.",
        )

    verification = verify_execution_permit(
        permit,
        engagement,
        test,
        request,
        keys,
    )
    if not verification.valid:
        return ConsumeResult(
            accepted=False,
            verification=verification,
            lifecycle_status=PermitLifecycleStatus.AVAILABLE,
            message="Permit verification failed; permit was not consumed.",
        )

    now = request.now or datetime.now(timezone.utc)
    try:
        entry = _consume_state(state_path, permit.payload.permit_id, now=now)
    except ValueError as exc:
        latest = permit_status(state_path, permit.payload.permit_id)
        return ConsumeResult(
            accepted=False,
            verification=verification,
            lifecycle_status=latest,
            message=str(exc),
        )
    return ConsumeResult(
        accepted=True,
        verification=verification,
        lifecycle_status=entry.status,
        message="Permit verified and consumed exactly once.",
    )


def _audit_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _read_audit_records(path: Path) -> list[AuditRecord]:
    if not path.exists():
        return []
    records: list[AuditRecord] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(AuditRecord.model_validate(json.loads(line)))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"invalid audit record at line {line_number}") from exc
    return records


def append_audit_event(
    path: Path,
    event: str,
    *,
    permit_id: str | None = None,
    details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> AuditRecord:
    records = _read_audit_records(path)
    previous_hash = records[-1].record_hash if records else GENESIS_HASH
    sequence = records[-1].sequence + 1 if records else 1
    timestamp = now or datetime.now(timezone.utc)
    unsigned_record = AuditRecord(
        schema_version=AUDIT_SCHEMA_VERSION,
        sequence=sequence,
        timestamp=timestamp,
        event=event,
        permit_id=permit_id,
        details=details or {},
        previous_hash=previous_hash,
        record_hash="pending",
    )
    unsigned = unsigned_record.model_dump(mode="json", exclude={"record_hash"})
    record = unsigned_record.model_copy(update={"record_hash": _audit_hash(unsigned)})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(record.model_dump(mode="json"), sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    return record


def verify_audit_chain(path: Path) -> tuple[bool, str]:
    records = _read_audit_records(path)
    previous_hash = GENESIS_HASH
    expected_sequence = 1
    for record in records:
        if record.sequence != expected_sequence:
            return False, f"Unexpected sequence at record {record.sequence}."
        if record.previous_hash != previous_hash:
            return False, f"Broken previous_hash link at record {record.sequence}."
        unsigned = record.model_dump(mode="json", exclude={"record_hash"})
        expected_hash = _audit_hash(unsigned)
        if expected_hash != record.record_hash:
            return False, f"Record hash mismatch at record {record.sequence}."
        previous_hash = record.record_hash
        expected_sequence += 1
    return True, f"Audit chain valid ({len(records)} records)."
