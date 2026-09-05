from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel


class SessionLedgerCounters(BaseModel):
    session_id: str
    actions_reserved: int
    requests_reserved: int
    errors: int
    completed: int
    updated_at: datetime


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS session_ledger (
            session_id TEXT PRIMARY KEY,
            actions_reserved INTEGER NOT NULL DEFAULT 0,
            requests_reserved INTEGER NOT NULL DEFAULT 0,
            errors INTEGER NOT NULL DEFAULT 0,
            completed INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    return connection


def initialize_session_ledger(path: Path, session_id: str) -> SessionLedgerCounters:
    now = datetime.now(UTC).isoformat()
    with _connect(path) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO session_ledger(session_id,updated_at) VALUES(?,?)",
            (session_id, now),
        )
    return get_session_counters(path, session_id)


def get_session_counters(path: Path, session_id: str) -> SessionLedgerCounters:
    with _connect(path) as connection:
        row = connection.execute(
            "SELECT * FROM session_ledger WHERE session_id=?", (session_id,)
        ).fetchone()
    if row is None:
        raise ValueError(f"unknown session: {session_id}")
    return SessionLedgerCounters(
        session_id=row["session_id"],
        actions_reserved=row["actions_reserved"],
        requests_reserved=row["requests_reserved"],
        errors=row["errors"],
        completed=row["completed"],
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


def reserve_action(
    path: Path,
    session_id: str,
    *,
    max_actions: int,
    max_requests: int,
) -> SessionLedgerCounters:
    if max_actions < 1 or max_requests < 1:
        raise ValueError("session budgets must be positive")
    now = datetime.now(UTC).isoformat()
    with _connect(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT actions_reserved,requests_reserved FROM session_ledger WHERE session_id=?",
            (session_id,),
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO session_ledger(session_id,updated_at) VALUES(?,?)",
                (session_id, now),
            )
            actions = 0
            requests = 0
        else:
            actions = int(row["actions_reserved"])
            requests = int(row["requests_reserved"])
        if actions >= max_actions:
            raise ValueError("action budget exhausted")
        if requests >= max_requests:
            raise ValueError("request budget exhausted")
        connection.execute(
            """
            UPDATE session_ledger
            SET actions_reserved=actions_reserved+1,
                requests_reserved=requests_reserved+1,
                updated_at=?
            WHERE session_id=?
            """,
            (now, session_id),
        )
    return get_session_counters(path, session_id)


def record_completion(
    path: Path, session_id: str, *, failed: bool = False
) -> SessionLedgerCounters:
    now = datetime.now(UTC).isoformat()
    with _connect(path) as connection:
        cursor = connection.execute(
            """
            UPDATE session_ledger
            SET completed=completed+1,
                errors=errors+?,
                updated_at=?
            WHERE session_id=?
            """,
            (1 if failed else 0, now, session_id),
        )
        if cursor.rowcount != 1:
            raise ValueError(f"unknown session: {session_id}")
    return get_session_counters(path, session_id)
