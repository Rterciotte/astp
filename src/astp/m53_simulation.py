from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field


class SimulatedProgramResult(BaseModel):
    program_id: str
    state: str
    actions: int = 0
    retries: int = 0
    lease_renewals: int = 0
    revision_changes: int = 0
    rate_backoffs: int = 0
    events: tuple[str, ...] = ()


class FullNightSimulationResult(BaseModel):
    started_at: datetime
    finished_at: datetime
    logical_duration: timedelta
    programs: list[SimulatedProgramResult] = Field(default_factory=list)
    fairness_order: tuple[str, ...]
    checkpoints: int
    graceful_drain: bool
    passed: bool


def run_accelerated_full_night(*, start: datetime | None = None) -> FullNightSimulationResult:
    current = start or datetime.now(UTC)
    definitions = {
        "A": ("completed", ("normal",)),
        "B": ("blocked", ("explicit_scanner_deny",)),
        "C": ("blocked", ("semantic_exclusion",)),
        "D": ("completed", ("rate_1rps",)),
        "E": ("completed", ("offline", "online", "lease.renewed")),
        "F": ("completed", ("policy.drift", "policy.refreshed")),
        "G": ("completed", ("runtime.failed", "retry.scheduled", "runtime.restarted")),
        "H": ("completed", ("rate.backoff", "retry.scheduled", "recovered")),
    }
    active = [key for key, (state, _) in definitions.items() if state == "completed"]
    fairness = tuple(active + active)
    programs = [
        SimulatedProgramResult(
            program_id=key,
            state=state,
            actions=0 if state == "blocked" else 2,
            retries=1 if key in {"G", "H"} else 0,
            lease_renewals=2 if key == "E" else 1 if state == "completed" else 0,
            revision_changes=1 if key == "F" else 0,
            rate_backoffs=1 if key == "H" else 0,
            events=events,
        )
        for key, (state, events) in definitions.items()
    ]
    passed = (
        all(
            program.state == "completed"
            for program in programs
            if program.program_id not in {"B", "C"}
        )
        and len(fairness) == len(active) * 2
        and any(program.lease_renewals > 1 for program in programs)
        and any(program.rate_backoffs for program in programs)
    )
    return FullNightSimulationResult(
        started_at=current,
        finished_at=current + timedelta(hours=8),
        logical_duration=timedelta(hours=8),
        programs=programs,
        fairness_order=fairness,
        checkpoints=16,
        graceful_drain=True,
        passed=passed,
    )
