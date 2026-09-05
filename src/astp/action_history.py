from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from astp.action import http_action_id


class ActionAdmission(BaseModel):
    admitted: bool
    action_id: str
    reason: str


def admit_unique_action(
    path: Path,
    *,
    engagement_id: str,
    test_id: str,
    target: str,
    method: str,
) -> ActionAdmission:
    action_id = http_action_id(target, method.upper(), f"{engagement_id}:{test_id}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS action_history "
            "(action_id TEXT PRIMARY KEY, completed_at TEXT NOT NULL)"
        )
        try:
            connection.execute(
                "INSERT INTO action_history VALUES (?, ?)",
                (action_id, datetime.now(UTC).isoformat()),
            )
        except sqlite3.IntegrityError:
            return ActionAdmission(admitted=False, action_id=action_id, reason="duplicate action")
    return ActionAdmission(admitted=True, action_id=action_id, reason="new action reserved")
