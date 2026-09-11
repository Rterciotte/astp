from __future__ import annotations

import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, Field


class NightAttemptOutcome(BaseModel):
    work_id: str
    program_id: str
    run_id: str
    permit_id: str
    status: str
    progress: bool
    retry_after_seconds: int | None = Field(default=None, ge=1)


class NightWork(BaseModel):
    work_id: str
    program_id: str
    duration_seconds: int = Field(ge=1)
    required_revision: str | None = None
    required_lease_id: str | None = None


class NightProgramState(BaseModel):
    program_id: str
    ready: bool = True
    revision: str = "1"
    lease_id: str | None = None
    pending: list[NightWork] = Field(default_factory=list)
    completed: list[str] = Field(default_factory=list)
    backoff_until: datetime | None = None
    consecutive_no_progress: int = 0
    exhausted_reason: str | None = None
    last_scheduled_round: int = 0
    fairness_rank: int = 0
    exhaust_on_empty_no_progress: bool = False


class NightSchedulerState(BaseModel):
    campaign_id: str
    started_at: datetime
    deadline: datetime
    now: datetime
    round_number: int = 0
    draining: bool = False
    programs: dict[str, NightProgramState]
    events: list[dict[str, object]] = Field(default_factory=list)


class DurableNightScheduler:
    """Small deterministic scheduler whose reportable facts live in durable state."""

    def __init__(self, path: Path):
        self.path = path

    def create(
        self, campaign_id: str, *, started_at: datetime, programs: tuple[NightProgramState, ...]
    ) -> NightSchedulerState:
        state = NightSchedulerState(
            campaign_id=campaign_id,
            started_at=started_at,
            deadline=started_at + timedelta(hours=8),
            now=started_at,
            programs={program.program_id: program for program in programs},
        )
        self.save(state)
        return state

    def reopen(self) -> NightSchedulerState:
        return NightSchedulerState.model_validate_json(self.path.read_text(encoding="utf-8"))

    def save(self, state: NightSchedulerState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{secrets.token_hex(4)}.tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(state.model_dump_json(indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.path)

    def advance(self, now: datetime) -> NightSchedulerState:
        state = self.reopen()
        if now.tzinfo is None or now.utcoffset() is None or now < state.now:
            raise ValueError("logical clock must advance monotonically with timezone")
        state.now = now
        state.round_number += 1
        state.draining = now >= state.deadline
        state.events.append(
            {"event": "clock.advanced", "at": now.isoformat(), "round": state.round_number}
        )
        self.save(state)
        return state

    def select(self) -> tuple[NightWork, ...]:
        state = self.reopen()
        if state.draining:
            return ()
        eligible = []
        for program in state.programs.values():
            if (
                program.ready
                and program.lease_id
                and program.pending
                and program.exhausted_reason is None
                and program.pending[0].required_revision in {None, program.revision}
                and program.pending[0].required_lease_id in {None, program.lease_id}
                and (program.backoff_until is None or state.now >= program.backoff_until)
                and state.now + timedelta(seconds=program.pending[0].duration_seconds)
                <= state.deadline
            ):
                eligible.append(program)
        eligible.sort(key=lambda row: (row.last_scheduled_round, row.fairness_rank, row.program_id))
        selected = tuple(program.pending[0] for program in eligible)
        for program in eligible:
            program.last_scheduled_round = state.round_number
        self.save(state)
        return selected

    def complete(self, work: NightWork, *, progress: bool) -> None:
        state = self.reopen()
        program = state.programs[work.program_id]
        if not program.pending or program.pending[0].work_id != work.work_id:
            raise ValueError("work is no longer current")
        program.pending.pop(0)
        program.completed.append(work.work_id)
        program.consecutive_no_progress = 0 if progress else program.consecutive_no_progress + 1
        if program.consecutive_no_progress >= 2 or (
            program.exhaust_on_empty_no_progress and not program.pending and not progress
        ):
            program.exhausted_reason = "bounded no-progress/candidate exhaustion"
        state.events.append(
            {"event": "work.completed", "work_id": work.work_id, "progress": progress}
        )
        self.save(state)

    def dispatch_round(self, executor) -> tuple[NightAttemptOutcome, ...]:
        """Launch exactly once per eligible decision, then durably ingest its outcome."""
        selected = self.select()
        outcomes = []
        for work in selected:
            outcome = NightAttemptOutcome.model_validate(executor(work))
            if outcome.work_id != work.work_id or outcome.program_id != work.program_id:
                raise ValueError("executor outcome does not match scheduler decision")
            state = self.reopen()
            state.events.append(
                {
                    "event": "attempt.finished",
                    "round": state.round_number,
                    **outcome.model_dump(mode="json"),
                }
            )
            self.save(state)
            if outcome.retry_after_seconds is not None:
                self.rate_limit(work.program_id, outcome.retry_after_seconds)
            self.complete(work, progress=outcome.progress)
            outcomes.append(outcome)
        return tuple(outcomes)

    def rate_limit(self, program_id: str, retry_after_seconds: int) -> datetime:
        if retry_after_seconds < 1:
            raise ValueError("Retry-After must be positive")
        state = self.reopen()
        until = state.now + timedelta(seconds=retry_after_seconds)
        state.programs[program_id].backoff_until = until
        state.events.append(
            {"event": "http.429", "program_id": program_id, "retry_at": until.isoformat()}
        )
        self.save(state)
        return until

    def apply_backoff_from_proxy_ledger(self, program_id: str, ledger_path: Path) -> datetime:
        with sqlite3.connect(ledger_path) as db:
            rows = db.execute(
                "SELECT detail FROM requests WHERE status=429 AND state='response_received'"
            ).fetchall()
        if len(rows) != 1 or not rows[0][0].startswith("retry_after_seconds="):
            raise ValueError("exactly one target 429 with Retry-After is required")
        return self.rate_limit(program_id, int(rows[0][0].split("=", 1)[1]))

    def replace_revision(self, program_id: str, revision: str, lease_id: str) -> None:
        state = self.reopen()
        program = state.programs[program_id]
        previous_revision, previous_lease = program.revision, program.lease_id
        program.revision = revision
        program.lease_id = lease_id
        program.pending = [
            work.model_copy(update={"required_revision": revision, "required_lease_id": lease_id})
            for work in program.pending
        ]
        state.events.append(
            {
                "event": "revision.replanned",
                "program_id": program_id,
                "from": previous_revision,
                "to": revision,
                "stale_lease": previous_lease,
                "fresh_lease": lease_id,
            }
        )
        self.save(state)

    def set_ready(self, program_id: str, *, ready: bool, lease_id: str | None = None) -> None:
        state = self.reopen()
        program = state.programs[program_id]
        program.ready = ready
        if lease_id is not None:
            program.lease_id = lease_id
            program.pending = [
                work.model_copy(update={"required_lease_id": lease_id}) for work in program.pending
            ]
        state.events.append(
            {
                "event": "program.ready" if ready else "program.offline",
                "program_id": program_id,
                "lease_id": program.lease_id,
            }
        )
        self.save(state)

    def replace_lease(self, program_id: str, lease_id: str) -> None:
        state = self.reopen()
        program = state.programs[program_id]
        previous = program.lease_id
        program.lease_id = lease_id
        program.pending = [
            work.model_copy(update={"required_lease_id": lease_id}) for work in program.pending
        ]
        state.events.append(
            {
                "event": "lease.replaced",
                "program_id": program_id,
                "stale_lease": previous,
                "fresh_lease": lease_id,
            }
        )
        self.save(state)

    def mark_retry(self, program_id: str, old_run_id: str, new_run_id: str) -> None:
        if old_run_id == new_run_id:
            raise ValueError("safe retry requires a fresh detector run")
        state = self.reopen()
        state.events.append(
            {
                "event": "runtime.retry",
                "program_id": program_id,
                "old_run_id": old_run_id,
                "new_run_id": new_run_id,
            }
        )
        self.save(state)

    def record_process_restart(self) -> None:
        state = self.reopen()
        state.events.append({"event": "process.reopened", "at": state.now.isoformat()})
        self.save(state)
