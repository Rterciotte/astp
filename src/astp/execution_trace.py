from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel


class ExecutionTraceEvent(BaseModel):
    sequence: int
    occurred_at: datetime
    event: str
    queue_id: str | None = None
    permit_id: str | None = None
    evidence_id: str | None = None
    message: str | None = None
    previous_hash: str | None = None
    event_hash: str


def _hash_payload(payload: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def append_trace_event(
    path: Path,
    event: str,
    *,
    queue_id: str | None = None,
    permit_id: str | None = None,
    evidence_id: str | None = None,
    message: str | None = None,
    now: datetime | None = None,
) -> ExecutionTraceEvent:
    path.parent.mkdir(parents=True, exist_ok=True)
    previous_hash: str | None = None
    sequence = 1
    if path.exists():
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            previous = ExecutionTraceEvent.model_validate_json(lines[-1])
            previous_hash = previous.event_hash
            sequence = previous.sequence + 1
    preliminary = ExecutionTraceEvent(
        sequence=sequence,
        occurred_at=now or datetime.now(UTC),
        event=event,
        queue_id=queue_id,
        permit_id=permit_id,
        evidence_id=evidence_id,
        message=message,
        previous_hash=previous_hash,
        event_hash="pending",
    )
    payload = preliminary.model_dump(mode="json", exclude={"event_hash"})
    row = preliminary.model_copy(update={"event_hash": _hash_payload(payload)})
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row.model_dump(mode="json"), sort_keys=True) + "\n")
    return row


def verify_execution_trace(path: Path) -> bool:
    previous_hash: str | None = None
    expected_sequence = 1
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = ExecutionTraceEvent.model_validate_json(line)
        if row.sequence != expected_sequence or row.previous_hash != previous_hash:
            return False
        payload = row.model_dump(mode="json", exclude={"event_hash"})
        if _hash_payload(payload) != row.event_hash:
            return False
        previous_hash = row.event_hash
        expected_sequence += 1
    return True
