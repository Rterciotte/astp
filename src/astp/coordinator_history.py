from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from astp.coordinator import CoordinatorStage
from astp.coordinator_gates import CoordinatorGateResult, StageGateDecision


class CoordinatorTransitionRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    engagement_id: str
    from_stage: CoordinatorStage
    to_stage: CoordinatorStage
    decision: StageGateDecision
    reason: str
    recorded_at: str


def initialize_transition_history(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS coordinator_transitions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id TEXT NOT NULL, "
            "from_stage TEXT NOT NULL, to_stage TEXT NOT NULL, decision TEXT NOT NULL, "
            "reason TEXT NOT NULL, recorded_at TEXT NOT NULL)"
        )


def record_transition(
    path: Path, engagement_id: str, result: CoordinatorGateResult
) -> CoordinatorTransitionRecord:
    initialize_transition_history(path)
    record = CoordinatorTransitionRecord(
        engagement_id=engagement_id,
        from_stage=result.from_stage,
        to_stage=result.to_stage,
        decision=result.decision,
        reason=result.reason,
        recorded_at=datetime.now(UTC).isoformat(),
    )
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO coordinator_transitions "
            "(engagement_id, from_stage, to_stage, decision, reason, recorded_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                record.engagement_id,
                record.from_stage.value,
                record.to_stage.value,
                record.decision.value,
                record.reason,
                record.recorded_at,
            ),
        )
    return record


def list_transition_history(
    path: Path, engagement_id: str
) -> tuple[CoordinatorTransitionRecord, ...]:
    initialize_transition_history(path)
    with sqlite3.connect(path) as db:
        rows = db.execute(
            "SELECT engagement_id, from_stage, to_stage, decision, reason, recorded_at "
            "FROM coordinator_transitions WHERE engagement_id = ? ORDER BY id",
            (engagement_id,),
        ).fetchall()
    return tuple(
        CoordinatorTransitionRecord(
            engagement_id=row[0],
            from_stage=CoordinatorStage(row[1]),
            to_stage=CoordinatorStage(row[2]),
            decision=StageGateDecision(row[3]),
            reason=row[4],
            recorded_at=row[5],
        )
        for row in rows
    )
