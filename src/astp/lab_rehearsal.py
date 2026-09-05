from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class LabRehearsalStage(StrEnum):
    AUTHORIZE = "authorize"
    QUALIFY_RUNTIMES = "qualify-runtimes"
    OBSERVE = "observe"
    INGEST_EVIDENCE = "ingest-evidence"
    REPLAN = "replan"
    VERIFY_SAFE_ACTIVE = "verify-safe-active"
    ASSERT_STATE_CHANGE_GATE = "assert-state-change-gate"
    REPORT = "report"
    REVIEW = "review"
    CLOSE = "close"


class LabRehearsalPlan(BaseModel):
    model_config = ConfigDict(frozen=True)
    stages: tuple[LabRehearsalStage, ...]
    requires_explicit_authorization: bool = True
    default_network_execution_enabled: bool = False
    can_mark_v1_ready: bool = False


def build_lab_rehearsal_plan() -> LabRehearsalPlan:
    return LabRehearsalPlan(stages=tuple(LabRehearsalStage))
