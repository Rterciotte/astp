from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from astp.verifier_action_compiler import CompiledVerificationAction


class VerificationDisposition(StrEnum):
    READY_FOR_POLICY = "ready_for_policy"
    PASSIVE_ONLY = "passive_only"
    BLOCKED = "blocked"


class ScheduledVerification(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: str
    verifier_id: str
    target: str
    disposition: VerificationDisposition
    fresh_permit_required: bool = True
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def schedule_verification_actions(
    actions: tuple[CompiledVerificationAction, ...],
    *,
    max_actions: int = 10,
) -> tuple[ScheduledVerification, ...]:
    if max_actions < 1:
        raise ValueError("max_actions must be positive")
    scheduled: list[ScheduledVerification] = []
    seen: set[tuple[str, str]] = set()
    for action in actions:
        key = (action.verifier_id, action.target)
        if key in seen:
            continue
        seen.add(key)
        scheduled.append(
            ScheduledVerification(
                action_id=action.id,
                verifier_id=action.verifier_id,
                target=action.target,
                disposition=VerificationDisposition.READY_FOR_POLICY,
            )
        )
        if len(scheduled) >= max_actions:
            break
    return tuple(scheduled)
