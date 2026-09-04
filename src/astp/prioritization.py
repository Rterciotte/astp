from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from astp.target_discovery import CandidateKind
from astp.target_registry import TargetRegistry


class PriorityReason(BaseModel):
    label: str
    weight: int


class PrioritizedTarget(BaseModel):
    target: str
    score: int
    reasons: list[PriorityReason] = Field(default_factory=list)


def prioritize_registry(registry: TargetRegistry) -> list[PrioritizedTarget]:
    rows: list[PrioritizedTarget] = []
    for entry in registry.entries:
        candidate = entry.latest_candidate
        score = 0
        reasons: list[PriorityReason] = []
        if candidate.in_scope:
            score += 50
            reasons.append(PriorityReason(label="in_scope", weight=50))
        if candidate.same_origin:
            score += 20
            reasons.append(PriorityReason(label="same_origin", weight=20))
        if candidate.kind == CandidateKind.REDIRECT:
            score += 10
            reasons.append(PriorityReason(label="observed_redirect", weight=10))
        path = urlsplit(entry.canonical_target).path or "/"
        depth = len([part for part in path.split("/") if part])
        if depth <= 2:
            score += 5
            reasons.append(PriorityReason(label="shallow_path", weight=5))
        score += min(len(entry.provenance), 5)
        if entry.provenance:
            reasons.append(
                PriorityReason(label="provenance_count", weight=min(len(entry.provenance), 5))
            )
        rows.append(PrioritizedTarget(target=entry.canonical_target, score=score, reasons=reasons))
    return sorted(rows, key=lambda item: (-item.score, item.target))
