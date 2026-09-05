from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict


class AssessmentRunStatus(StrEnum):
    PREPARED = "prepared"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class AssessmentRunState(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    engagement_id: str
    status: AssessmentRunStatus
    policy_digest: str
    completed_action_ids: tuple[str, ...] = ()
    failed_action_ids: tuple[str, ...] = ()
    updated_at: datetime


def save_assessment_run_state(path: Path, state: AssessmentRunState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS assessment_runs ("
            "run_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT OR REPLACE INTO assessment_runs VALUES (?, ?, ?)",
            (state.run_id, state.model_dump_json(), state.updated_at.isoformat()),
        )


def load_assessment_run_state(path: Path, run_id: str) -> AssessmentRunState | None:
    if not path.exists():
        return None
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS assessment_runs ("
            "run_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        row = connection.execute(
            "SELECT payload FROM assessment_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    return AssessmentRunState.model_validate(json.loads(row[0])) if row else None


def new_assessment_run_state(
    run_id: str, engagement_id: str, policy_digest: str
) -> AssessmentRunState:
    return AssessmentRunState(
        run_id=run_id,
        engagement_id=engagement_id,
        status=AssessmentRunStatus.PREPARED,
        policy_digest=policy_digest,
        updated_at=datetime.now(UTC),
    )
