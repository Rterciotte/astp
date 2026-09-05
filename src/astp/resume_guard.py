from __future__ import annotations

from pydantic import BaseModel, Field

from astp.planner_state import PlannerItemState, PlannerStateEntry


class ResumeDecision(BaseModel):
    allowed: bool
    resumable_queue_ids: list[str] = Field(default_factory=list)
    blocked_queue_ids: list[str] = Field(default_factory=list)
    reason: str


def evaluate_resume(entries: list[PlannerStateEntry]) -> ResumeDecision:
    resumable: list[str] = []
    blocked: list[str] = []
    for entry in entries:
        if entry.state in {PlannerItemState.QUEUED, PlannerItemState.FAILED}:
            resumable.append(entry.queue_id)
        else:
            blocked.append(entry.queue_id)
    return ResumeDecision(
        allowed=bool(resumable),
        resumable_queue_ids=resumable,
        blocked_queue_ids=blocked,
        reason=(
            "only queued or failed items may be re-planned; issued/running/completed items "
            "are never blindly resumed"
        ),
    )
