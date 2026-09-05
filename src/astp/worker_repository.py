from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from astp.worker_job import WorkerJobEnvelope, WorkerJobStatus


def _init(connection: sqlite3.Connection) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS worker_jobs ("
        "id TEXT PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL)"
    )


def store_worker_job(path: Path, job: WorkerJobEnvelope) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        _init(connection)
        connection.execute(
            "INSERT OR REPLACE INTO worker_jobs VALUES (?, ?, ?)",
            (job.id, WorkerJobStatus.PREPARED.value, job.model_dump_json()),
        )


def update_worker_job_status(path: Path, job_id: str, status: WorkerJobStatus) -> None:
    with sqlite3.connect(path) as connection:
        _init(connection)
        cursor = connection.execute(
            "UPDATE worker_jobs SET status = ? WHERE id = ?", (status.value, job_id)
        )
        if cursor.rowcount != 1:
            raise ValueError("worker job does not exist")


def load_worker_job(path: Path, job_id: str) -> tuple[WorkerJobEnvelope, WorkerJobStatus]:
    with sqlite3.connect(path) as connection:
        _init(connection)
        row = connection.execute(
            "SELECT payload, status FROM worker_jobs WHERE id = ?", (job_id,)
        ).fetchone()
    if row is None:
        raise ValueError("worker job does not exist")
    return WorkerJobEnvelope.model_validate(json.loads(row[0])), WorkerJobStatus(row[1])
