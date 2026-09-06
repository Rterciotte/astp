from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from astp.field_execution_status import evaluate_field_execution


def _write_trace(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_dns_failure_is_not_reported_as_completed_assessment(tmp_path: Path) -> None:
    session_id = "field-session"
    trace = tmp_path / "trace.jsonl"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    _write_trace(
        trace,
        [
            {"event": "session.started"},
            {"event": "permit.issued", "permit_id": "permit-1"},
            {"event": "session.finished", "message": "failure circuit breaker opened"},
        ],
    )
    (evidence_dir / f"{session_id}-field-0001.json").write_text(
        json.dumps({"evidence_id": "ev-fail", "failure_kind": "dns"}),
        encoding="utf-8",
    )

    status = evaluate_field_execution(
        session_id=session_id,
        trace_path=trace,
        evidence_dir=evidence_dir,
        now=datetime(2026, 9, 6, tzinfo=UTC),
    )

    assert status.execution_succeeded is False
    assert status.completed_actions == 0
    assert status.failed_actions == 1
    assert status.permits_issued == 1
    assert status.failure_kinds == ("dns",)
    assert status.network_state == "DNS_RESOLUTION_FAILED_BEFORE_TARGET_CONNECTION"


def test_one_response_backed_observation_is_success(tmp_path: Path) -> None:
    session_id = "field-session"
    trace = tmp_path / "trace.jsonl"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    _write_trace(trace, [{"event": "permit.issued", "permit_id": "permit-1"}])
    (evidence_dir / f"{session_id}-field-0001.json").write_text(
        json.dumps({"evidence_id": "ev-ok", "status_code": 301}),
        encoding="utf-8",
    )

    status = evaluate_field_execution(
        session_id=session_id,
        trace_path=trace,
        evidence_dir=evidence_dir,
        now=datetime(2026, 9, 6, tzinfo=UTC),
    )

    assert status.execution_succeeded is True
    assert status.completed_actions == 1
    assert status.failed_actions == 0
    assert status.network_state == "HTTP_RESPONSE_OBSERVED"


def test_permit_without_response_evidence_fails_closed(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    _write_trace(trace, [{"event": "permit.issued", "permit_id": "permit-1"}])

    status = evaluate_field_execution(
        session_id="field-session",
        trace_path=trace,
        evidence_dir=evidence_dir,
        now=datetime(2026, 9, 6, tzinfo=UTC),
    )

    assert status.execution_succeeded is False
    assert status.network_state == "TARGET_NETWORK_IO_NOT_PROVEN"
    assert "permit was issued" in status.reason
