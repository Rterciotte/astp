from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from astp.detector_registry import ProofRequirement, VulnerabilityFamily


class ProofStateV2(StrEnum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    CANDIDATE = "candidate"
    REPRODUCED = "reproduced"
    CONFIRMED = "confirmed"
    IMPACT_DEMONSTRATED = "impact_demonstrated"
    BLOCKED = "blocked"


class DetectorProof(BaseModel):
    vulnerability_family: VulnerabilityFamily
    requirement: ProofRequirement
    state: ProofStateV2
    evidence_ids: tuple[str, ...] = ()
    reason: str
    tool_id: str
    tool_version: str
    action_id: str | None = None
    permit_id: str | None = None
    confidence: float = Field(ge=0, le=1)


def proof_ceiling(family: VulnerabilityFamily, *, signal_only: bool) -> ProofStateV2:
    if signal_only:
        return ProofStateV2.SUSPECTED
    if family in {VulnerabilityFamily.REFLECTED_XSS, VulnerabilityFamily.DOM_XSS}:
        return ProofStateV2.CANDIDATE
    if family is VulnerabilityFamily.IDOR:
        return ProofStateV2.CANDIDATE
    if family is VulnerabilityFamily.SQL_INJECTION:
        return ProofStateV2.CANDIDATE
    if family is VulnerabilityFamily.KNOWN_CVE:
        return ProofStateV2.CANDIDATE
    if family is VulnerabilityFamily.SSRF:
        return ProofStateV2.CANDIDATE
    return ProofStateV2.REPRODUCED
