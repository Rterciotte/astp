from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator


class CampaignState(StrEnum):
    CREATED = "created"
    PREFLIGHT = "preflight"
    READY = "ready"
    RUNNING = "running"
    PAUSING = "pausing"
    PAUSED = "paused"
    DRAINING = "draining"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ProgramState(StrEnum):
    DISCOVERED = "discovered"
    SYNCING = "syncing"
    POLICY_REVIEW = "policy_review"
    WAITING_OPERATIONAL = "waiting_operational"
    WAITING_PREREQUISITE = "waiting_prerequisite"
    READY = "ready"
    PLANNING = "planning"
    RUNNING = "running"
    REPLANNING = "replanning"
    BLOCKED = "blocked"
    EXHAUSTED = "exhausted"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ActionState(StrEnum):
    DISCOVERED = "discovered"
    UNPLANNED = "unplanned"
    PLANNED = "planned"
    AUTHORIZED = "authorized"
    PERMIT_ISSUED = "permit_issued"
    STARTING = "starting"
    EXECUTING = "executing"
    EVIDENCE_RECORDED = "evidence_recorded"
    VERIFIED = "verified"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"
    SUPERSEDED = "superseded"


class CampaignReadiness(StrEnum):
    FULL_UNATTENDED_READY = "full_unattended_ready"
    DEGRADED_COVERAGE = "degraded_coverage"
    BLOCKED = "blocked"


def evaluate_readiness(
    *, required_prerequisites_blocked: bool, optional_capabilities_unavailable: bool
) -> CampaignReadiness:
    if required_prerequisites_blocked:
        return CampaignReadiness.BLOCKED
    if optional_capabilities_unavailable:
        return CampaignReadiness.DEGRADED_COVERAGE
    return CampaignReadiness.FULL_UNATTENDED_READY


CAMPAIGN_TRANSITIONS = {
    CampaignState.CREATED: {CampaignState.PREFLIGHT, CampaignState.CANCELLED},
    CampaignState.PREFLIGHT: {CampaignState.READY, CampaignState.BLOCKED, CampaignState.FAILED},
    CampaignState.READY: {CampaignState.RUNNING, CampaignState.CANCELLED},
    CampaignState.RUNNING: {
        CampaignState.PAUSING,
        CampaignState.DRAINING,
        CampaignState.COMPLETED,
        CampaignState.PARTIALLY_COMPLETED,
        CampaignState.FAILED,
    },
    CampaignState.PAUSING: {CampaignState.PAUSED, CampaignState.FAILED},
    CampaignState.PAUSED: {CampaignState.PREFLIGHT, CampaignState.CANCELLED},
    CampaignState.DRAINING: {
        CampaignState.COMPLETED,
        CampaignState.PARTIALLY_COMPLETED,
        CampaignState.PAUSED,
    },
}
ACTION_TRANSITIONS = {
    ActionState.DISCOVERED: {ActionState.UNPLANNED, ActionState.BLOCKED},
    ActionState.UNPLANNED: {ActionState.PLANNED, ActionState.BLOCKED},
    ActionState.PLANNED: {ActionState.AUTHORIZED, ActionState.BLOCKED, ActionState.SUPERSEDED},
    ActionState.AUTHORIZED: {ActionState.PERMIT_ISSUED, ActionState.BLOCKED},
    ActionState.PERMIT_ISSUED: {
        ActionState.STARTING,
        ActionState.BLOCKED,
        ActionState.UNKNOWN_OUTCOME,
    },
    ActionState.STARTING: {ActionState.EXECUTING, ActionState.FAILED, ActionState.UNKNOWN_OUTCOME},
    ActionState.EXECUTING: {
        ActionState.EVIDENCE_RECORDED,
        ActionState.FAILED,
        ActionState.UNKNOWN_OUTCOME,
    },
    ActionState.EVIDENCE_RECORDED: {ActionState.VERIFIED, ActionState.FAILED},
    ActionState.VERIFIED: {ActionState.COMPLETED, ActionState.BLOCKED},
}


class AutonomousCampaignConfig(BaseModel):
    campaign_id: str
    platforms: tuple[str, ...] = ("bughunt",)
    selected_program_ids: tuple[str, ...] = ()
    include_all_ready_programs: bool = False
    max_duration: timedelta = timedelta(hours=8)
    global_action_budget: int = Field(default=200, ge=1)
    global_request_budget: int = Field(default=200, ge=1)
    per_program_action_budget: int = Field(default=30, ge=1)
    per_program_request_budget: int = Field(default=30, ge=1)
    per_detector_budget: int = Field(default=20, ge=1)
    max_concurrent_programs: int = Field(default=2, ge=1, le=8)
    max_concurrent_actions: int = Field(default=1, ge=1, le=4)
    max_errors_global: int = Field(default=10, ge=1)
    max_errors_per_program: int = Field(default=3, ge=1)
    max_consecutive_failures: int = Field(default=2, ge=1)
    max_rounds_per_program: int = Field(default=5, ge=1)
    max_new_targets_per_round: int = Field(default=20, ge=1)
    max_discovery_depth: int = Field(default=3, ge=0)
    max_detector_iterations: int = Field(default=3, ge=1)
    default_rate_ceiling: float = Field(default=1.0, gt=0, le=5)
    report_interval: timedelta = timedelta(minutes=10)
    checkpoint_interval: timedelta = timedelta(minutes=2)
    operational_refresh_interval: timedelta = timedelta(minutes=3)
    program_refresh_interval: timedelta = timedelta(minutes=30)
    runtime_health_interval: timedelta = timedelta(minutes=5)
    stop_when_no_progress: int = Field(default=2, ge=1)
    minimum_remaining_time_for_new_action: timedelta = timedelta(minutes=5)
    dry_run: bool = True
    execute: bool = False
    resume_if_safe: bool = False

    @model_validator(mode="after")
    def validate_execution(self) -> AutonomousCampaignConfig:
        if self.execute == self.dry_run:
            raise ValueError("exactly one of execute or dry_run must be true")
        if not self.selected_program_ids and not self.include_all_ready_programs:
            raise ValueError("select programs or include all ready programs")
        return self


class StateTransition(BaseModel):
    entity_type: str
    entity_id: str
    previous_state: str
    state: str
    timestamp: datetime
    reason: str
    actor: str
    related_action_id: str | None = None
    permit_id: str | None = None
    evidence_id: str | None = None


def validate_transition(previous: StrEnum, new: StrEnum, transitions: dict) -> None:
    if new not in transitions.get(previous, set()):
        raise ValueError(f"invalid state transition: {previous.value} -> {new.value}")
