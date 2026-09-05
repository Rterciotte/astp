from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class SessionDecision(StrEnum):
    CONTINUE = "continue"
    REPLAN = "replan"
    STOP = "stop"


class AssessmentSessionState(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str
    engagement_id: str
    actions_executed: int = 0
    requests_executed: int = 0
    errors: int = 0
    evidence_ids: tuple[str, ...] = Field(default_factory=tuple)
    pending_action_ids: tuple[str, ...] = Field(default_factory=tuple)
    decision: SessionDecision = SessionDecision.CONTINUE
    stop_reason: str | None = None
    network_execution_enabled: bool = False
    fresh_permit_per_action: bool = True


def evaluate_session_progress(
    state: AssessmentSessionState,
    *,
    new_evidence_ids: tuple[str, ...] = (),
    new_pending_action_ids: tuple[str, ...] = (),
    error_budget: int = 1,
    action_budget: int = 10,
) -> AssessmentSessionState:
    evidence_ids = tuple(dict.fromkeys((*state.evidence_ids, *new_evidence_ids)))
    pending = tuple(dict.fromkeys((*state.pending_action_ids, *new_pending_action_ids)))
    if state.errors >= error_budget:
        decision = SessionDecision.STOP
        reason = "error budget exhausted"
    elif state.actions_executed >= action_budget:
        decision = SessionDecision.STOP
        reason = "action budget exhausted"
    elif new_evidence_ids or new_pending_action_ids:
        decision = SessionDecision.REPLAN
        reason = None
    else:
        decision = SessionDecision.CONTINUE
        reason = None
    return state.model_copy(
        update={
            "evidence_ids": evidence_ids,
            "pending_action_ids": pending,
            "decision": decision,
            "stop_reason": reason,
        }
    )


def save_session_state(path: Path, state: AssessmentSessionState) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(state.model_dump_json(indent=2) + "\n", encoding="utf-8")


def load_session_state(path: Path) -> AssessmentSessionState:
    return AssessmentSessionState.model_validate_json(path.read_text(encoding="utf-8"))
