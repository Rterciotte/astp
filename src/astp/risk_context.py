from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from astp.findings import CorrelatedFinding, ProofState


class Exposure(str, Enum):
    UNKNOWN = "unknown"
    INTERNAL = "internal"
    AUTHENTICATED = "authenticated"
    INTERNET = "internet"


class AssetImportance(str, Enum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskContext(BaseModel):
    exposure: Exposure = Exposure.UNKNOWN
    asset_importance: AssetImportance = AssetImportance.UNKNOWN
    exploitability_hint: float | None = Field(default=None, ge=0, le=1)
    epss: float | None = Field(default=None, ge=0, le=1)
    kev_listed: bool | None = None


class ContextualRiskScore(BaseModel):
    score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    rationale: list[str]
    is_cvss: bool = False


def score_finding_context(
    finding: CorrelatedFinding,
    context: RiskContext,
) -> ContextualRiskScore:
    proof_weight = {
        ProofState.SUSPECTED: 10,
        ProofState.LIKELY: 25,
        ProofState.VERIFIED: 45,
        ProofState.IMPACT_CONFIRMED: 60,
    }[finding.proof_state]
    exposure_weight = {
        Exposure.UNKNOWN: 0,
        Exposure.INTERNAL: 3,
        Exposure.AUTHENTICATED: 7,
        Exposure.INTERNET: 12,
    }[context.exposure]
    asset_weight = {
        AssetImportance.UNKNOWN: 0,
        AssetImportance.LOW: 2,
        AssetImportance.MEDIUM: 6,
        AssetImportance.HIGH: 12,
        AssetImportance.CRITICAL: 18,
    }[context.asset_importance]
    score = float(proof_weight + exposure_weight + asset_weight)
    rationale = [
        f"proof_state={finding.proof_state.value}",
        f"exposure={context.exposure.value}",
        f"asset_importance={context.asset_importance.value}",
    ]
    if context.exploitability_hint is not None:
        score += context.exploitability_hint * 6
        rationale.append("exploitability_hint supplied")
    if context.epss is not None:
        score += context.epss * 3
        rationale.append("EPSS supplied as contextual input")
    if context.kev_listed:
        score += 8
        rationale.append("KEV-listed contextual input")
    known = sum(
        value is not None
        for value in (context.exploitability_hint, context.epss, context.kev_listed)
    )
    confidence = min(1.0, 0.45 + known * 0.1)
    return ContextualRiskScore(
        score=round(min(score, 100.0), 2),
        confidence=round(confidence, 2),
        rationale=rationale,
    )
