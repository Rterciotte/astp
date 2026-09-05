from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel


class QuarantinedEvidence(BaseModel):
    evidence_id: str
    reason: str
    quarantined_at: datetime


def quarantine_evidence(path: Path, evidence_id: str, reason: str) -> QuarantinedEvidence:
    if not reason.strip():
        raise ValueError("quarantine reason is required")
    item = QuarantinedEvidence(
        evidence_id=evidence_id,
        reason=reason.strip(),
        quarantined_at=datetime.now(UTC),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS evidence_quarantine ("
            "evidence_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT OR REPLACE INTO evidence_quarantine VALUES (?, ?)",
            (evidence_id, item.model_dump_json()),
        )
    return item


def list_quarantined_evidence(path: Path) -> list[QuarantinedEvidence]:
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS evidence_quarantine ("
            "evidence_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
        )
        rows = connection.execute(
            "SELECT payload FROM evidence_quarantine ORDER BY evidence_id"
        ).fetchall()
    return [QuarantinedEvidence.model_validate(json.loads(row[0])) for row in rows]
