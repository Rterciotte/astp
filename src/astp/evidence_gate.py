from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class EvidenceAcceptanceContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: str
    manifest_verified: bool
    action_id_matches: bool
    engagement_id_matches: bool
    quarantined: bool = False
    provenance_complete: bool = True


class EvidenceAcceptanceResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    accepted: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_evidence_acceptance(context: EvidenceAcceptanceContext) -> EvidenceAcceptanceResult:
    blockers: list[str] = []
    if not context.manifest_verified:
        blockers.append("evidence manifest verification failed")
    if not context.action_id_matches:
        blockers.append("evidence action id does not match the authorized action")
    if not context.engagement_id_matches:
        blockers.append("evidence engagement does not match the active assessment")
    if context.quarantined:
        blockers.append("evidence is quarantined")
    if not context.provenance_complete:
        blockers.append("evidence provenance is incomplete")
    return EvidenceAcceptanceResult(accepted=not blockers, blockers=tuple(blockers))
