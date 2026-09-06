from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from astp.program_models import BugBountyProgram, ProgramImportStatus


class PortfolioProgramState(BaseModel):
    model_config = ConfigDict(frozen=True)

    program_id: str
    name: str
    status: ProgramImportStatus
    unresolved_blockers: int
    reviewed_rps: float | None = None
    evidence_namespace: str
    queue_eligible: bool


class PortfolioPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    programs: tuple[PortfolioProgramState, ...] = Field(default_factory=tuple)
    fair_queue_order: tuple[str, ...] = Field(default_factory=tuple)
    independent_policy_and_evidence: bool = True
    execution_enabled: bool = False


def build_portfolio_plan(programs: list[BugBountyProgram]) -> PortfolioPlan:
    if not programs:
        raise ValueError("at least one program is required")
    ids = [program.id for program in programs]
    if len(ids) != len(set(ids)):
        raise ValueError("portfolio contains duplicate program ids")

    states = tuple(
        PortfolioProgramState(
            program_id=program.id,
            name=program.name,
            status=program.status,
            unresolved_blockers=len(program.unresolved_issues),
            reviewed_rps=program.reviewed_max_requests_per_second,
            evidence_namespace=str(Path(".astp") / "programs" / program.id / "evidence"),
            queue_eligible=program.status is ProgramImportStatus.READY,
        )
        for program in sorted(programs, key=lambda item: item.id)
    )
    ready = tuple(state.program_id for state in states if state.queue_eligible)
    digest = hashlib.sha256("|".join(ids).encode()).hexdigest()[:16]
    return PortfolioPlan(id=f"portfolio-{digest}", programs=states, fair_queue_order=ready)
