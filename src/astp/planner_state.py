from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from astp.work_queue import WorkQueue


class PlannerItemState(str, Enum):
    QUEUED = "queued"
    PERMIT_ISSUED = "permit_issued"
    RUNNING = "running"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


_ALLOWED_TRANSITIONS = {
    PlannerItemState.QUEUED: {PlannerItemState.PERMIT_ISSUED, PlannerItemState.BLOCKED},
    PlannerItemState.PERMIT_ISSUED: {PlannerItemState.RUNNING, PlannerItemState.BLOCKED},
    PlannerItemState.RUNNING: {PlannerItemState.COMPLETED, PlannerItemState.FAILED},
    PlannerItemState.FAILED: {PlannerItemState.QUEUED, PlannerItemState.BLOCKED},
    PlannerItemState.COMPLETED: set(),
    PlannerItemState.BLOCKED: set(),
}


class PlannerStateEntry(BaseModel):
    queue_id: str
    state: PlannerItemState
    permit_id: str | None = None
    evidence_id: str | None = None
    attempts: int = 0
    message: str | None = None
    updated_at: datetime


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS planner_items (
            queue_id TEXT PRIMARY KEY,
            state TEXT NOT NULL,
            permit_id TEXT,
            evidence_id TEXT,
            attempts INTEGER NOT NULL DEFAULT 0,
            message TEXT,
            updated_at TEXT NOT NULL
        )
        """
    )
    return connection


def initialize_planner_state(path: Path, queue: WorkQueue) -> None:
    now = datetime.now(UTC).isoformat()
    with _connect(path) as connection:
        for item in queue.items:
            connection.execute(
                "INSERT OR IGNORE INTO planner_items(queue_id,state,updated_at) VALUES(?,?,?)",
                (item.queue_id, PlannerItemState.QUEUED.value, now),
            )


def get_planner_state(path: Path, queue_id: str) -> PlannerStateEntry:
    with _connect(path) as connection:
        row = connection.execute(
            "SELECT queue_id,state,permit_id,evidence_id,attempts,message,updated_at "
            "FROM planner_items WHERE queue_id=?",
            (queue_id,),
        ).fetchone()
    if row is None:
        raise ValueError(f"unknown queue item: {queue_id}")
    return PlannerStateEntry(
        queue_id=row["queue_id"],
        state=PlannerItemState(row["state"]),
        permit_id=row["permit_id"],
        evidence_id=row["evidence_id"],
        attempts=row["attempts"],
        message=row["message"],
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


def transition_planner_state(
    path: Path,
    queue_id: str,
    new_state: PlannerItemState,
    *,
    permit_id: str | None = None,
    evidence_id: str | None = None,
    message: str | None = None,
) -> PlannerStateEntry:
    current = get_planner_state(path, queue_id)
    if new_state not in _ALLOWED_TRANSITIONS[current.state]:
        raise ValueError(
            "invalid planner state transition: " f"{current.state.value} -> {new_state.value}"
        )
    attempts = current.attempts + (1 if new_state == PlannerItemState.RUNNING else 0)
    now = datetime.now(UTC).isoformat()
    with _connect(path) as connection:
        connection.execute(
            """
            UPDATE planner_items
            SET state=?, permit_id=COALESCE(?, permit_id), evidence_id=COALESCE(?, evidence_id),
                attempts=?, message=?, updated_at=?
            WHERE queue_id=?
            """,
            (new_state.value, permit_id, evidence_id, attempts, message, now, queue_id),
        )
    return get_planner_state(path, queue_id)
