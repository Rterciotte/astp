from __future__ import annotations

from collections import defaultdict

from pydantic import BaseModel, Field

from astp.findings import FindingSignal
from astp.signal_normalizer import NormalizedSignal


class ConfidenceFusion(BaseModel):
    key: str
    fused_confidence: float = Field(ge=0, le=1)
    contributing_sources: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


def fuse_probabilities(values: list[float]) -> float:
    """Conservatively combine independent confidence contributions."""
    if not values:
        return 0.0
    residual = 1.0
    for value in values:
        bounded = min(1.0, max(0.0, value))
        residual *= 1.0 - bounded
    return round(1.0 - residual, 6)


def fuse_normalized_signals(signals: list[NormalizedSignal]) -> list[ConfidenceFusion]:
    grouped: dict[str, list[NormalizedSignal]] = defaultdict(list)
    for signal in signals:
        grouped[signal.key].append(signal)
    results: list[ConfidenceFusion] = []
    for key, rows in sorted(grouped.items()):
        results.append(
            ConfidenceFusion(
                key=key,
                fused_confidence=fuse_probabilities([row.confidence for row in rows]),
                contributing_sources=sorted({row.signal_class.value for row in rows}),
                evidence_ids=sorted({row.evidence_id for row in rows}),
            )
        )
    return results


def fused_finding_signal_confidence(signals: list[FindingSignal]) -> float:
    return fuse_probabilities([signal.confidence for signal in signals])
