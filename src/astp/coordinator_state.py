from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from astp.coordinator import CoordinatorStage


def initialize_coordinator_state(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS coordinator_state (engagement_id TEXT PRIMARY KEY, stage TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )


def set_coordinator_stage(path: Path, engagement_id: str, stage: CoordinatorStage) -> None:
    initialize_coordinator_state(path)
    now = datetime.now(UTC).isoformat()
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO coordinator_state VALUES (?, ?, ?) ON CONFLICT(engagement_id) DO UPDATE SET stage=excluded.stage, updated_at=excluded.updated_at",
            (engagement_id, stage.value, now),
        )
