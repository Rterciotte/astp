from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.active_verifier_registry import ActiveVerifierDefinition, ActiveVerifierRisk


class VerificationExecutionContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    verifier_id: str
    permit_id: str | None = None
    approval_id: str | None = None
    policy_allowed: bool = False
    attestation_fresh: bool = False


class VerificationExecutionDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    executable: bool
    autonomous_execution_allowed: bool = False
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_verification_execution(
    verifier: ActiveVerifierDefinition,
    context: VerificationExecutionContext,
) -> VerificationExecutionDecision:
    reasons: list[str] = []
    if verifier.id != context.verifier_id:
        reasons.append("verifier context does not match definition")
    if not context.policy_allowed:
        reasons.append("policy has not allowed the verification action")
    if not context.attestation_fresh:
        reasons.append("operational attestation is not fresh")
    if verifier.requires_fresh_permit and not context.permit_id:
        reasons.append("fresh execution permit is required")
    if verifier.risk is ActiveVerifierRisk.STATE_CHANGING and not context.approval_id:
        reasons.append("state-changing verifier requires exact operator approval")
    executable = not reasons
    return VerificationExecutionDecision(
        executable=executable,
        autonomous_execution_allowed=executable
        and verifier.risk is ActiveVerifierRisk.SAFE_ACTIVE
        and verifier.autonomous_execution_allowed,
        reasons=tuple(reasons),
    )
