from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from astp.execution_intent import ExecutionIntent


class AssessmentRunState(StrEnum):
    PREPARED = "prepared"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    BLOCKED = "blocked"


class AssessmentExecutionPlan(BaseModel):
    schema_version: str = "1"
    id: str
    engagement_id: str
    state: AssessmentRunState = AssessmentRunState.PREPARED
    intents: list[ExecutionIntent] = Field(default_factory=list)
    max_network_actions: int = Field(default=20, ge=0, le=1000)
    max_errors: int = Field(default=3, ge=0, le=100)
    created_at: datetime
    execution_enabled: bool = False


def build_assessment_execution_plan(
    engagement_id: str,
    intents: list[ExecutionIntent],
    *,
    max_network_actions: int = 20,
    max_errors: int = 3,
    execution_enabled: bool = False,
) -> AssessmentExecutionPlan:
    raw = json.dumps([engagement_id, [item.id for item in intents]], separators=(",", ":")).encode()
    return AssessmentExecutionPlan(
        id="assessment-run-" + hashlib.sha256(raw).hexdigest()[:16],
        engagement_id=engagement_id,
        intents=intents,
        max_network_actions=max_network_actions,
        max_errors=max_errors,
        created_at=datetime.now(UTC),
        execution_enabled=execution_enabled,
    )


def write_assessment_execution_plan(plan: AssessmentExecutionPlan, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
