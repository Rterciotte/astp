from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel

from astp.finding_lifecycle import FindingStatus
from astp.findings import CorrelatedFinding


class FindingRepositoryRecord(BaseModel):
    finding: CorrelatedFinding
    status: FindingStatus
    updated_at: datetime
    retest_required: bool = False


def _initialize(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS findings ("
        "finding_id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL, "
        "retest_required INTEGER NOT NULL, updated_at TEXT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS finding_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL, event TEXT NOT NULL, "
        "payload TEXT, created_at TEXT NOT NULL)"
    )


def upsert_finding(path: Path, finding: CorrelatedFinding) -> FindingRepositoryRecord:
    path.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    with sqlite3.connect(path) as connection:
        _initialize(connection)
        connection.execute(
            "INSERT INTO findings VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(finding_id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
            (
                finding.id,
                json.dumps(finding.model_dump(mode="json"), sort_keys=True),
                FindingStatus.OPEN.value,
                0,
                now.isoformat(),
            ),
        )
        connection.execute(
            "INSERT INTO finding_events(finding_id, event, payload, created_at) VALUES (?, ?, ?, ?)",
            (finding.id, "finding.upserted", None, now.isoformat()),
        )
    return get_finding(path, finding.id)


def set_retest_state(path: Path, finding_id: str, *, required: bool) -> FindingRepositoryRecord:
    with sqlite3.connect(path) as connection:
        _initialize(connection)
        row = connection.execute(
            "SELECT payload FROM findings WHERE finding_id = ?", (finding_id,)
        ).fetchone()
        if row is None:
            raise ValueError("unknown finding")
        now = datetime.now(UTC)
        status = FindingStatus.RETEST_REQUIRED if required else FindingStatus.OPEN
        connection.execute(
            "UPDATE findings SET status = ?, retest_required = ?, updated_at = ? WHERE finding_id = ?",
            (status.value, int(required), now.isoformat(), finding_id),
        )
        connection.execute(
            "INSERT INTO finding_events(finding_id, event, payload, created_at) VALUES (?, ?, ?, ?)",
            (
                finding_id,
                "retest.requested" if required else "retest.cleared",
                None,
                now.isoformat(),
            ),
        )
    return get_finding(path, finding_id)


def resolve_finding(path: Path, finding_id: str) -> FindingRepositoryRecord:
    with sqlite3.connect(path) as connection:
        _initialize(connection)
        now = datetime.now(UTC)
        cursor = connection.execute(
            "UPDATE findings SET status = ?, retest_required = 0, updated_at = ? WHERE finding_id = ?",
            (FindingStatus.RESOLVED.value, now.isoformat(), finding_id),
        )
        if cursor.rowcount == 0:
            raise ValueError("unknown finding")
        connection.execute(
            "INSERT INTO finding_events(finding_id, event, payload, created_at) VALUES (?, ?, ?, ?)",
            (finding_id, "finding.resolved", None, now.isoformat()),
        )
    return get_finding(path, finding_id)


def get_finding(path: Path, finding_id: str) -> FindingRepositoryRecord:
    with sqlite3.connect(path) as connection:
        _initialize(connection)
        row = connection.execute(
            "SELECT payload, status, retest_required, updated_at FROM findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
    if row is None:
        raise ValueError("unknown finding")
    return FindingRepositoryRecord(
        finding=CorrelatedFinding.model_validate(json.loads(row[0])),
        status=FindingStatus(row[1]),
        retest_required=bool(row[2]),
        updated_at=datetime.fromisoformat(row[3]),
    )
