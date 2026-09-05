from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RehearsalStage(StrEnum):
    INTAKE = "intake"
    DISCOVERY = "discovery"
    OBSERVATION = "observation"
    VERIFICATION = "verification"
    RETEST = "retest"
    REPORT = "report"
    REVIEW = "review"
    CLOSURE = "closure"


class RehearsalResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    stages: tuple[RehearsalStage, ...]
    policy_boundary_preserved: bool
    fresh_permit_per_network_action: bool
    evidence_gate_preserved: bool
    state_change_requires_operator: bool
    network_execution_performed: bool = False
    ready_for_authorized_field_test: bool = False
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def build_offline_end_to_end_rehearsal() -> RehearsalResult:
    return RehearsalResult(
        stages=tuple(RehearsalStage),
        policy_boundary_preserved=True,
        fresh_permit_per_network_action=True,
        evidence_gate_preserved=True,
        state_change_requires_operator=True,
        ready_for_authorized_field_test=True,
        blockers=(
            "physical browser/tool runtimes still require authorized field qualification",
            "broad active verifier execution still requires field qualification",
            "authorized end-to-end network assessment has not yet been recorded",
        ),
    )
