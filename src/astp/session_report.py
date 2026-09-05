from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from astp.execution_trace import ExecutionTraceEvent
from astp.session_ledger import SessionLedgerCounters


class SessionExecutionSummary(BaseModel):
    session_id: str
    actions_reserved: int
    requests_reserved: int
    completed: int
    errors: int
    permits_issued: int
    evidence_records: int
    events: list[str] = Field(default_factory=list)


def summarize_session_execution(
    counters: SessionLedgerCounters,
    trace_path: Path,
) -> SessionExecutionSummary:
    events: list[ExecutionTraceEvent] = []
    if trace_path.exists():
        for line in trace_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(ExecutionTraceEvent.model_validate(json.loads(line)))
    return SessionExecutionSummary(
        session_id=counters.session_id,
        actions_reserved=counters.actions_reserved,
        requests_reserved=counters.requests_reserved,
        completed=counters.completed,
        errors=counters.errors,
        permits_issued=sum(1 for item in events if item.event == "permit.issued"),
        evidence_records=sum(1 for item in events if item.event == "evidence.recorded"),
        events=[item.event for item in events],
    )
