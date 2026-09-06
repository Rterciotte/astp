from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FieldExecutionStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    session_id: str
    evaluated_at: datetime
    execution_succeeded: bool
    completed_actions: int
    failed_actions: int
    permits_issued: int
    success_evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    failure_evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    failure_kinds: tuple[str, ...] = Field(default_factory=tuple)
    network_state: str
    reason: str
    status_hash: str


def _sha256_json(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_json_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def _load_session_evidence(evidence_dir: Path, session_id: str) -> list[dict[str, Any]]:
    if not evidence_dir.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(evidence_dir.glob(f"{session_id}-*.json")):
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(item, dict):
            records.append(item)
    return records


def _network_state(success_count: int, failure_kinds: tuple[str, ...]) -> str:
    if success_count:
        return "HTTP_RESPONSE_OBSERVED"
    if "dns" in failure_kinds:
        return "DNS_RESOLUTION_FAILED_BEFORE_TARGET_CONNECTION"
    if any(kind in {"connection", "tls", "timeout", "io"} for kind in failure_kinds):
        return "TARGET_CONNECTION_OR_HTTP_ATTEMPT_FAILED"
    return "TARGET_NETWORK_IO_NOT_PROVEN"


def evaluate_field_execution(
    *,
    session_id: str,
    trace_path: Path,
    evidence_dir: Path,
    now: datetime | None = None,
) -> FieldExecutionStatus:
    trace = _load_json_lines(trace_path)
    evidence = _load_session_evidence(evidence_dir, session_id)

    permits_issued = sum(1 for row in trace if row.get("event") == "permit.issued")
    success_records = [row for row in evidence if isinstance(row.get("status_code"), int)]
    failure_records = [row for row in evidence if isinstance(row.get("failure_kind"), str)]
    success_ids = tuple(
        str(row.get("evidence_id")) for row in success_records if row.get("evidence_id")
    )
    failure_ids = tuple(
        str(row.get("evidence_id")) for row in failure_records if row.get("evidence_id")
    )
    failure_kinds = tuple(sorted({str(row["failure_kind"]) for row in failure_records}))

    # M46.6 is intentionally a one-action bootstrap. It is successful only when one
    # response-backed observation exists and no transport-failure record exists.
    execution_succeeded = len(success_records) == 1 and not failure_records
    failed_actions = 0 if execution_succeeded else 1
    state = _network_state(len(success_records), failure_kinds)

    if execution_succeeded:
        reason = "exactly one response-backed bounded observation completed"
    elif failure_kinds:
        reason = "bounded observation failed: " + ", ".join(failure_kinds)
    elif permits_issued:
        reason = "permit was issued but response-backed execution evidence was not produced"
    else:
        reason = "bounded action did not produce response-backed execution evidence"

    payload: dict[str, object] = {
        "schema_version": "1",
        "session_id": session_id,
        "evaluated_at": (now or datetime.now(UTC)).isoformat(),
        "execution_succeeded": execution_succeeded,
        "completed_actions": len(success_records),
        "failed_actions": failed_actions,
        "permits_issued": permits_issued,
        "success_evidence_ids": success_ids,
        "failure_evidence_ids": failure_ids,
        "failure_kinds": failure_kinds,
        "network_state": state,
        "reason": reason,
    }
    payload["status_hash"] = _sha256_json(payload)
    return FieldExecutionStatus.model_validate(payload)


def _persist_json_immutable(path: Path, payload: dict[str, object]) -> None:
    rendered = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError(f"immutable field-execution status collision: {path}")
        return
    path.write_text(rendered, encoding="utf-8")


def _write_failure_record(path: Path, status: FieldExecutionStatus) -> None:
    lines = [
        "# ASTP Bounded Field Execution Failure",
        "",
        f"Session: `{status.session_id}`",
        f"Evaluated: {status.evaluated_at.isoformat()}",
        f"Network state: `{status.network_state}`",
        f"Permits issued: {status.permits_issued}",
        f"Completed actions: {status.completed_actions}",
        f"Failed actions: {status.failed_actions}",
        f"Reason: {status.reason}",
        "",
        "No successful HTTP observation is claimed by this record.",
        "The original failure evidence and hash-linked execution trace remain authoritative.",
        "",
    ]
    rendered = "\n".join(lines)
    if path.exists():
        if path.read_text(encoding="utf-8") != rendered:
            raise ValueError(f"immutable failure-record collision: {path}")
        return
    path.write_text(rendered, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify one bounded field-execution outcome")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    status = evaluate_field_execution(
        session_id=args.session_id,
        trace_path=args.trace,
        evidence_dir=args.evidence_dir,
    )
    status_path = args.output_dir / f"execution-status-{status.status_hash}.json"
    _persist_json_immutable(status_path, status.model_dump(mode="json"))
    failure_path = args.output_dir / "execution-failure.md"
    if not status.execution_succeeded:
        _write_failure_record(failure_path, status)

    rendered = {
        **status.model_dump(mode="json"),
        "status_path": str(status_path),
        "failure_record_path": str(failure_path) if not status.execution_succeeded else None,
    }
    print(json.dumps(rendered, indent=2, sort_keys=True))
    print(
        "FIELD_EXECUTION_STATUS: SUCCESS"
        if status.execution_succeeded
        else "FIELD_EXECUTION_STATUS: FAILED"
    )
    return 0 if status.execution_succeeded else 3


if __name__ == "__main__":
    raise SystemExit(main())
