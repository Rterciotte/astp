from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from astp.safe_verification_executor import SafeVerificationResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS verification_results (
    envelope_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_id TEXT,
    reason TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    payload_json TEXT NOT NULL
)
"""


def record_verification_result(path: Path, result: SafeVerificationResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(SCHEMA)
        conn.execute(
            """
            INSERT OR REPLACE INTO verification_results
            (envelope_id, action_id, status, evidence_id, reason, recorded_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.envelope_id,
                result.action_id,
                result.status.value,
                result.evidence_id,
                result.reason,
                datetime.now(UTC).isoformat(),
                result.model_dump_json(),
            ),
        )
        conn.commit()


def load_verification_result(path: Path, envelope_id: str) -> SafeVerificationResult | None:
    if not path.exists():
        return None
    with sqlite3.connect(path) as conn:
        conn.execute(SCHEMA)
        row = conn.execute(
            "SELECT payload_json FROM verification_results WHERE envelope_id = ?",
            (envelope_id,),
        ).fetchone()
    return None if row is None else SafeVerificationResult.model_validate(json.loads(row[0]))
