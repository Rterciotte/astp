from __future__ import annotations

from pydantic import BaseModel

from astp.models import Engagement, ProgramOperationalAttestation, TestDefinition
from astp.planner import ObservationPlan, PlanItemStatus, build_observation_plan
from astp.target_registry import TargetRegistry


class ReplanResult(BaseModel):
    plan: ObservationPlan
    new_authorizable_items: int


def replan_registry(
    registry: TargetRegistry,
    engagement: Engagement,
    test: TestDefinition,
    *,
    previous_targets: set[str] | None = None,
    semantic_exclusion_clears: set[str] | None = None,
    operational_attestation: ProgramOperationalAttestation | None = None,
    requested_rps: float | None = None,
) -> ReplanResult:
    if registry.engagement_id != engagement.id:
        raise ValueError("registry belongs to a different engagement")
    plan = build_observation_plan(
        registry,
        engagement,
        test,
        semantic_exclusion_clears=semantic_exclusion_clears,
        operational_attestation=operational_attestation,
        requested_rps=requested_rps,
    )
    prior = previous_targets or set()
    count = sum(
        item.status == PlanItemStatus.AUTHORIZABLE and item.target not in prior
        for item in plan.items
    )
    return ReplanResult(plan=plan, new_authorizable_items=count)
