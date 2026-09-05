from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from astp.findings import CorrelatedFinding
from astp.verification_plan import FindingVerificationPlan


class VerificationQueueStatus(str, Enum):
    QUEUED = "queued"
    REVIEW_REQUIRED = "review_required"
    AUTHORIZABLE = "authorizable"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class VerificationQueueItem(BaseModel):
    id: str
    finding_id: str
    status: VerificationQueueStatus
    plan: FindingVerificationPlan
    created_at: datetime


def _initialize(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS verification_queue ("
        "id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, status TEXT NOT NULL, "
        "payload TEXT NOT NULL, created_at TEXT NOT NULL)"
    )


def enqueue_verification(
    path: Path,
    finding: CorrelatedFinding,
    plan: FindingVerificationPlan,
) -> VerificationQueueItem:
    now = datetime.now(UTC)
    item_id = f"verify-{finding.id}"
    item = VerificationQueueItem(
        id=item_id,
        finding_id=finding.id,
        status=VerificationQueueStatus.REVIEW_REQUIRED,
        plan=plan,
        created_at=now,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        _initialize(connection)
        connection.execute(
            "INSERT OR REPLACE INTO verification_queue VALUES (?, ?, ?, ?, ?)",
            (
                item.id,
                item.finding_id,
                item.status.value,
                json.dumps(item.model_dump(mode="json"), sort_keys=True),
                now.isoformat(),
            ),
        )
    return item


def list_verification_queue(path: Path) -> list[VerificationQueueItem]:
    with sqlite3.connect(path) as connection:
        _initialize(connection)
        rows = connection.execute(
            "SELECT payload FROM verification_queue ORDER BY created_at, id"
        ).fetchall()
    return [VerificationQueueItem.model_validate(json.loads(row[0])) for row in rows]
