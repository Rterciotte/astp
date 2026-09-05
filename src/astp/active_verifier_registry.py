from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class ActiveVerifierRisk(StrEnum):
    SAFE_ACTIVE = "safe_active"
    STATE_CHANGING = "state_changing"


class ActiveVerifierDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    family: str
    risk: ActiveVerifierRisk
    requires_fresh_permit: bool = True
    requires_distinct_identity: bool = False
    proof_ceiling: str = "likely"
    autonomous_execution_allowed: bool = False


def builtin_active_verifiers() -> tuple[ActiveVerifierDefinition, ...]:
    return (
        ActiveVerifierDefinition(
            id="authorization.object-access.v2",
            family="authorization",
            risk=ActiveVerifierRisk.SAFE_ACTIVE,
            requires_distinct_identity=True,
            proof_ceiling="likely",
        ),
        ActiveVerifierDefinition(
            id="cors.controlled-origin.v1",
            family="cors",
            risk=ActiveVerifierRisk.SAFE_ACTIVE,
            proof_ceiling="likely",
        ),
        ActiveVerifierDefinition(
            id="cache.variation.v1",
            family="cache",
            risk=ActiveVerifierRisk.SAFE_ACTIVE,
            proof_ceiling="likely",
        ),
        ActiveVerifierDefinition(
            id="redirect.authorization-boundary.v1",
            family="redirect",
            risk=ActiveVerifierRisk.SAFE_ACTIVE,
            proof_ceiling="likely",
        ),
        ActiveVerifierDefinition(
            id="session.state-change.v1",
            family="session",
            risk=ActiveVerifierRisk.STATE_CHANGING,
            proof_ceiling="suspected",
        ),
    )
