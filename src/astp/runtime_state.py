from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from astp.lifecycle import PermitLifecycleStatus
from astp.models import Engagement, TestDefinition
from astp.permits import (
    PermitVerificationRequest,
    PermitVerificationResult,
    SignedExecutionPermit,
    verify_execution_permit,
)

RUNTIME_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class WorkerAdmissionResult:
    accepted: bool
    verification: PermitVerificationResult
    lifecycle_status: PermitLifecycleStatus
    message: str
    retry_after_seconds: float = 0.0


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=10000")
    connection.execute("PRAGMA foreign_keys=ON")
    for attempt in range(20):
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            break
        except sqlite3.OperationalError as exc:
            if "locked" not in str(exc).lower() or attempt == 19:
                connection.close()
                raise
            time.sleep(0.025)
    _initialize(connection)
    return connection


def _initialize(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS permit_state (
            permit_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            reason TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS rate_events (
            action_key TEXT NOT NULL,
            observed_at REAL NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_rate_events_key_time "
        "ON rate_events(action_key, observed_at)"
    )
    connection.execute(
        "INSERT OR IGNORE INTO runtime_meta(key, value) VALUES('schema_version', ?)",
        (str(RUNTIME_SCHEMA_VERSION),),
    )


def runtime_permit_status(path: Path, permit_id: str) -> PermitLifecycleStatus:
    with _connect(path) as connection:
        row = connection.execute(
            "SELECT status FROM permit_state WHERE permit_id = ?", (permit_id,)
        ).fetchone()
    if row is None:
        return PermitLifecycleStatus.AVAILABLE
    return PermitLifecycleStatus(row["status"])


def revoke_runtime_permit(
    path: Path,
    permit_id: str,
    *,
    reason: str,
    now: datetime | None = None,
) -> PermitLifecycleStatus:
    current = now or datetime.now(UTC)
    with _connect(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT status FROM permit_state WHERE permit_id = ?", (permit_id,)
        ).fetchone()
        if row is not None and row["status"] == PermitLifecycleStatus.CONSUMED.value:
            connection.execute("ROLLBACK")
            raise ValueError("a consumed permit cannot be retroactively revoked")
        connection.execute(
            """
            INSERT INTO permit_state(permit_id, status, updated_at, reason)
            VALUES(?, ?, ?, ?)
            ON CONFLICT(permit_id) DO UPDATE SET
                status = excluded.status,
                updated_at = excluded.updated_at,
                reason = excluded.reason
            """,
            (
                permit_id,
                PermitLifecycleStatus.REVOKED.value,
                current.isoformat(),
                reason,
            ),
        )
        connection.execute("COMMIT")
    return PermitLifecycleStatus.REVOKED


def admit_worker_action(
    permit: SignedExecutionPermit,
    engagement: Engagement,
    test: TestDefinition,
    request: PermitVerificationRequest,
    keys: str | bytes | dict[str, str | bytes],
    runtime_db_path: Path,
    *,
    action_key: str,
    max_requests_per_second: float,
) -> WorkerAdmissionResult:
    """Verify, rate-admit, and consume one permit in a single SQLite transaction."""
    if max_requests_per_second <= 0:
        raise ValueError("Rate limit must be greater than zero.")

    verification = verify_execution_permit(permit, engagement, test, request, keys)
    if not verification.valid:
        return WorkerAdmissionResult(
            accepted=False,
            verification=verification,
            lifecycle_status=PermitLifecycleStatus.AVAILABLE,
            message="Permit verification failed; permit was not consumed.",
        )

    now = request.now or datetime.now(UTC)
    instant = now.timestamp()
    minimum_interval = 1.0 / max_requests_per_second
    window_start = instant - 1.0
    permit_id = permit.payload.permit_id

    with _connect(runtime_db_path) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT status FROM permit_state WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if row is not None:
                status = PermitLifecycleStatus(row["status"])
                if status == PermitLifecycleStatus.REVOKED:
                    connection.execute("ROLLBACK")
                    return WorkerAdmissionResult(
                        accepted=False,
                        verification=verification,
                        lifecycle_status=status,
                        message="Permit has been revoked.",
                    )
                if status == PermitLifecycleStatus.CONSUMED:
                    connection.execute("ROLLBACK")
                    return WorkerAdmissionResult(
                        accepted=False,
                        verification=verification,
                        lifecycle_status=status,
                        message="Permit has already been consumed; replay rejected.",
                    )

            connection.execute(
                "DELETE FROM rate_events WHERE action_key = ? AND observed_at <= ?",
                (action_key, window_start),
            )
            latest = connection.execute(
                "SELECT MAX(observed_at) AS latest FROM rate_events WHERE action_key = ?",
                (action_key,),
            ).fetchone()["latest"]
            if latest is not None and instant - float(latest) < minimum_interval:
                retry_after = max(0.0, minimum_interval - (instant - float(latest)))
                connection.execute("ROLLBACK")
                return WorkerAdmissionResult(
                    accepted=False,
                    verification=verification,
                    lifecycle_status=PermitLifecycleStatus.AVAILABLE,
                    message="Durable target rate limit reached; permit was not consumed.",
                    retry_after_seconds=retry_after,
                )

            connection.execute(
                "INSERT INTO rate_events(action_key, observed_at) VALUES(?, ?)",
                (action_key, instant),
            )
            connection.execute(
                """
                INSERT INTO permit_state(permit_id, status, updated_at, reason)
                VALUES(?, ?, ?, NULL)
                """,
                (permit_id, PermitLifecycleStatus.CONSUMED.value, now.isoformat()),
            )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            connection.execute("ROLLBACK")
            status = runtime_permit_status(runtime_db_path, permit_id)
            return WorkerAdmissionResult(
                accepted=False,
                verification=verification,
                lifecycle_status=status,
                message="Permit admission raced with another worker; replay rejected.",
            )
        except BaseException:
            connection.execute("ROLLBACK")
            raise

    return WorkerAdmissionResult(
        accepted=True,
        verification=verification,
        lifecycle_status=PermitLifecycleStatus.CONSUMED,
        message="Permit verified, rate-admitted, and consumed atomically.",
    )
