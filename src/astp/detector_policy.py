from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from astp.detector_registry import DetectorCapability, RuntimeState


class MentionDisposition(StrEnum):
    EXPLICITLY_ALLOWED = "explicitly_allowed"
    EXPLICITLY_DENIED = "explicitly_denied"
    NOT_MENTIONED = "not_mentioned"
    REQUIRES_CONTEXT = "requires_context"


class DetectorDecisionCode(StrEnum):
    ALLOWED = "allowed"
    EXPLICITLY_DENIED = "explicitly_denied"
    BLOCKED_SCOPE = "blocked_scope"
    BLOCKED_SEMANTIC_EXCLUSION = "blocked_semantic_exclusion"
    BLOCKED_OPERATIONAL = "blocked_operational"
    BLOCKED_PREREQUISITE = "blocked_prerequisite"
    BLOCKED_BUDGET = "blocked_budget"
    BLOCKED_RUNTIME = "blocked_runtime"
    REQUIRES_REVIEW = "requires_review"


class DetectorPolicyContext(BaseModel):
    disposition: MentionDisposition = MentionDisposition.NOT_MENTIONED
    applicable_general_denials: tuple[str, ...] = ()
    target_in_scope: bool
    semantic_review_complete: bool = True
    operational: bool = True
    available_identities: int = 0
    oast_available: bool = False
    browser_available: bool = False
    remaining_requests: int = Field(ge=0)
    provenance: tuple[str, ...] = ()


class DetectorPolicyDecision(BaseModel):
    detector_id: str
    code: DetectorDecisionCode
    allowed: bool
    reason: str
    evidence: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()


def decide_detector(
    capability: DetectorCapability, context: DetectorPolicyContext
) -> DetectorPolicyDecision:
    def result(code: DetectorDecisionCode, reason: str) -> DetectorPolicyDecision:
        return DetectorPolicyDecision(
            detector_id=capability.detector_id,
            code=code,
            allowed=code is DetectorDecisionCode.ALLOWED,
            reason=reason,
            evidence=context.applicable_general_denials,
            provenance=context.provenance,
        )

    if (
        context.disposition is MentionDisposition.EXPLICITLY_DENIED
        or context.applicable_general_denials
    ):
        return result(
            DetectorDecisionCode.EXPLICITLY_DENIED,
            "an explicit tool/technique or applicable general prohibition blocks execution",
        )
    if not context.target_in_scope:
        return result(DetectorDecisionCode.BLOCKED_SCOPE, "target is not unambiguously in scope")
    if not context.semantic_review_complete:
        return result(
            DetectorDecisionCode.BLOCKED_SEMANTIC_EXCLUSION,
            "target-bound semantic exclusion review is incomplete",
        )
    if not context.operational:
        return result(DetectorDecisionCode.BLOCKED_OPERATIONAL, "program operational gate failed")
    if capability.runtime_state is not RuntimeState.QUALIFIED or not capability.field_ready:
        return result(
            DetectorDecisionCode.BLOCKED_RUNTIME,
            "runtime is unavailable, unqualified, or not field-ready",
        )
    if capability.identities_required > context.available_identities:
        return result(
            DetectorDecisionCode.BLOCKED_PREREQUISITE, "required identities are unavailable"
        )
    if capability.oast_required and not context.oast_available:
        return result(DetectorDecisionCode.BLOCKED_PREREQUISITE, "OAST provider is unavailable")
    if capability.browser_required and not context.browser_available:
        return result(
            DetectorDecisionCode.BLOCKED_PREREQUISITE, "qualified browser runtime is unavailable"
        )
    if context.remaining_requests <= 0:
        return result(DetectorDecisionCode.BLOCKED_BUDGET, "no request budget remains")
    if context.disposition is MentionDisposition.REQUIRES_CONTEXT:
        return result(
            DetectorDecisionCode.REQUIRES_REVIEW, "policy requires additional factual context"
        )
    return result(
        DetectorDecisionCode.ALLOWED,
        "no applicable explicit prohibition; all scope, operational, prerequisite, runtime, and budget gates passed",
    )
