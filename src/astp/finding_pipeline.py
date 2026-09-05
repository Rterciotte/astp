from __future__ import annotations

from pydantic import BaseModel, Field

from astp.findings import FindingCandidate, FindingSignal, ProofState
from astp.signal_normalizer import NormalizedSignal


class CandidatePipelineResult(BaseModel):
    candidates: list[FindingCandidate] = Field(default_factory=list)
    suppressed_signal_keys: list[str] = Field(default_factory=list)


def build_finding_candidates(
    signals: list[NormalizedSignal],
    *,
    excluded_finding_terms: set[str] | None = None,
) -> CandidatePipelineResult:
    excluded = {item.lower() for item in (excluded_finding_terms or set())}
    candidates: list[FindingCandidate] = []
    suppressed: list[str] = []
    for signal in signals:
        if not signal.eligible_for_finding_candidate:
            suppressed.append(signal.key)
            continue
        combined = f"{signal.key} {signal.observation}".lower()
        if any(term in combined for term in excluded):
            suppressed.append(signal.key)
            continue
        candidates.append(
            FindingCandidate(
                vulnerability=signal.key,
                asset=signal.target,
                endpoint=signal.target,
                proof_state=(
                    ProofState.VERIFIED if signal.confirmed_vulnerability else ProofState.SUSPECTED
                ),
                signals=[
                    FindingSignal(
                        sensor="signal-normalizer",
                        evidence_id=signal.evidence_id,
                        observation=signal.observation,
                        confidence=signal.confidence,
                    )
                ],
            )
        )
    return CandidatePipelineResult(candidates=candidates, suppressed_signal_keys=suppressed)
