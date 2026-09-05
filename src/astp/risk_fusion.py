from __future__ import annotations

from pydantic import BaseModel

from astp.findings import CorrelatedFinding, ProofState
from astp.risk_context import ContextualRiskScore, RiskContext, score_finding_context


class FusedRiskAssessment(BaseModel):
    finding_id: str
    contextual: ContextualRiskScore
    confidence: float
    proof_multiplier: float
    fused_score: float
    is_cvss: bool = False


def fuse_finding_risk(
    finding: CorrelatedFinding,
    context: RiskContext,
    *,
    confidence: float,
) -> FusedRiskAssessment:
    confidence = min(1.0, max(0.0, confidence))
    contextual = score_finding_context(finding, context)
    proof_weights = {
        ProofState.SUSPECTED: 0.45,
        ProofState.LIKELY: 0.65,
        ProofState.VERIFIED: 0.85,
        ProofState.IMPACT_CONFIRMED: 1.0,
    }
    multiplier = proof_weights[finding.proof_state]
    fused = round(contextual.score * (0.5 + confidence / 2) * multiplier, 2)
    return FusedRiskAssessment(
        finding_id=finding.id,
        contextual=contextual,
        confidence=confidence,
        proof_multiplier=multiplier,
        fused_score=fused,
    )
