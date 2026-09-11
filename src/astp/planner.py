from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.authorization import AuthorizationRequest, authorize_test
from astp.models import Decision, Engagement, ProgramOperationalAttestation, TestDefinition
from astp.operational_lease import ProgramOperationalLease
from astp.target_discovery import CandidateSafety
from astp.target_registry import TargetRegistry


class PlanItemStatus(str, Enum):
    AUTHORIZABLE = "authorizable"
    BLOCKED_POLICY = "blocked_policy"
    BLOCKED_CONTEXT = "blocked_context"
    REJECTED_DISCOVERY = "rejected_discovery"


class TargetSemanticAssessment(BaseModel):
    """Explicit semantic deny-guardrail assessment bound to one exact target."""

    semantic_exclusion_clears: set[str] = Field(default_factory=set)
    semantic_exclusion_matches: set[str] = Field(default_factory=set)


class ObservationPlanItem(BaseModel):
    id: str
    target: str
    method: str = "GET"
    status: PlanItemStatus
    authorization_decision: Decision | None = None
    reason: str
    source_candidate_ids: list[str] = Field(default_factory=list)
    semantic_exclusion_clears: set[str] = Field(default_factory=set)
    semantic_exclusion_matches: set[str] = Field(default_factory=set)
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
    semantic_target_assessments: dict[str, TargetSemanticAssessment] | None = None,
    operational_attestation: ProgramOperationalAttestation | None = None,
    operational_lease: ProgramOperationalLease | None = None,
    operational_lease_store_path: str | None = None,
    requested_rps: float | None = None,
    now: datetime | None = None,
) -> ObservationPlan:
    """Build a non-executing plan.

    ``semantic_exclusion_clears`` is retained for backward-compatible workflows that
    deliberately apply one reviewed clearance set to the whole registry.
    ``semantic_target_assessments`` is the safer target-bound form used by nightly
    campaigns. The two forms are intentionally mutually exclusive so a global
    clearance cannot silently override target-specific review.
    """
    if semantic_exclusion_clears is not None and semantic_target_assessments is not None:
        raise ValueError(
            "global semantic_exclusion_clears cannot be combined with "
            "semantic_target_assessments"
        )

    current = now or datetime.now(UTC)
    global_clears = set(semantic_exclusion_clears or set())
    assessments = semantic_target_assessments or {}
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

        if semantic_target_assessments is not None:
            assessment = assessments.get(entry.canonical_target, TargetSemanticAssessment())
            clears = set(assessment.semantic_exclusion_clears)
            matches = set(assessment.semantic_exclusion_matches)
        else:
            clears = set(global_clears)
            matches = set()

        request = AuthorizationRequest(
            target=entry.canonical_target,
            http_method="GET",
            requested_requests_per_second=requested_rps,
            program_operational_attestation=operational_attestation,
            program_operational_lease=operational_lease,
            operational_lease_store_path=operational_lease_store_path,
            semantic_exclusion_clears=clears,
            semantic_exclusion_matches=matches,
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
            blockers = [
                check.message for check in result.checks if check.status.value in {"review", "fail"}
            ]
            reason = "; ".join(blockers) or (
                "Authorization requires additional context or explicit approval."
            )
        else:
            status = PlanItemStatus.BLOCKED_POLICY
            blockers = [check.message for check in result.checks if check.status.value == "fail"]
            reason = "; ".join(blockers) or "Current engagement policy denies this proposed action."
        items.append(
            ObservationPlanItem(
                id=f"plan-{index:04d}",
                target=entry.canonical_target,
                status=status,
                authorization_decision=result.decision,
                reason=reason,
                source_candidate_ids=list(entry.candidate_ids),
                semantic_exclusion_clears=clears,
                semantic_exclusion_matches=matches,
            )
        )

    return ObservationPlan(
        engagement_id=engagement.id,
        test_id=test.id,
        created_at=current,
        items=items,
    )
