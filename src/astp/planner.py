from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.authorization import AuthorizationRequest, authorize_test
from astp.models import Decision, Engagement, ProgramOperationalAttestation, TestDefinition
from astp.target_discovery import CandidateSafety
from astp.target_registry import TargetRegistry


class PlanItemStatus(str, Enum):
    AUTHORIZABLE = "authorizable"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_CONTEXT = "blocked_context"
    REJECTED_DISCOVERY = "rejected_discovery"


class ObservationPlanItem(BaseModel):
    id: str
    target: str
    method: str = "GET"
    status: PlanItemStatus
    authorization_decision: Decision | None = None
    reason: str
    source_candidate_ids: list[str] = Field(default_factory=list)
    semantic_exclusion_clears: set[str] = Field(default_factory=set)
    requires_new_permit: bool = True
    permit_id: str | None = None


class ObservationPlan(BaseModel):
    schema_version: str = "1"
    engagement_id: str
    test_id: str
    created_at: datetime
    items: list[ObservationPlanItem] = Field(default_factory=list)


def build_observation_plan(
    registry: TargetRegistry,
    engagement: Engagement,
    test: TestDefinition,
    *,
    semantic_exclusion_clears: set[str] | None = None,
    operational_attestation: ProgramOperationalAttestation | None = None,
    requested_rps: float | None = None,
    now: datetime | None = None,
) -> ObservationPlan:
    current = now or datetime.now(UTC)
    clears = set(semantic_exclusion_clears or set())
    items: list[ObservationPlanItem] = []

    for index, entry in enumerate(registry.entries, start=1):
        candidate = entry.latest_candidate
        if candidate.safety != CandidateSafety.READY_FOR_POLICY:
            items.append(
                ObservationPlanItem(
                    id=f"plan-{index:04d}",
                    target=entry.canonical_target,
                    status=PlanItemStatus.REJECTED_DISCOVERY,
                    reason=candidate.reason,
                    source_candidate_ids=list(entry.candidate_ids),
                )
            )
            continue

        request = AuthorizationRequest(
            target=entry.canonical_target,
            http_method="GET",
            requested_requests_per_second=requested_rps,
            program_operational_attestation=operational_attestation,
            semantic_exclusion_clears=clears,
            semantic_exclusion_matches=set(),
            now=current,
        )
        result = authorize_test(engagement, test, request)
        if result.decision == Decision.ALLOW:
            status = PlanItemStatus.AUTHORIZABLE
            reason = (
                "Policy allows this exact proposed action; a new signed permit is still required."
            )
        elif result.decision in {Decision.INSUFFICIENT_CONTEXT, Decision.APPROVAL_REQUIRED}:
            status = PlanItemStatus.BLOCKED_CONTEXT
            reason = "Authorization requires additional context or explicit approval."
        else:
            status = PlanItemStatus.BLOCKED_POLICY
            reason = "Current engagement policy denies this proposed action."
        items.append(
            ObservationPlanItem(
                id=f"plan-{index:04d}",
                target=entry.canonical_target,
                status=status,
                authorization_decision=result.decision,
                reason=reason,
                source_candidate_ids=list(entry.candidate_ids),
                semantic_exclusion_clears=clears,
            )
        )

    return ObservationPlan(
        engagement_id=engagement.id,
        test_id=test.id,
        created_at=current,
        items=items,
    )
