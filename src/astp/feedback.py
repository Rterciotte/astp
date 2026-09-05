from __future__ import annotations

from pydantic import BaseModel

from astp.models import Engagement
from astp.observation import HttpObservationEvidence
from astp.target_discovery import TargetDiscoveryResult, discover_targets_from_evidence
from astp.target_registry import TargetRegistry, merge_discovery


class FeedbackResult(BaseModel):
    discovered: TargetDiscoveryResult
    registry: TargetRegistry
    added_entries: int


def apply_evidence_feedback(
    evidence: HttpObservationEvidence,
    engagement: Engagement,
    registry: TargetRegistry,
    *,
    include_links: bool = True,
    max_candidates: int = 50,
) -> FeedbackResult:
    before = len(registry.entries)
    discovered = discover_targets_from_evidence(
        evidence,
        engagement,
        include_links=include_links,
        max_link_candidates=max_candidates,
    )
    updated = merge_discovery(registry, discovered)
    return FeedbackResult(
        discovered=discovered,
        registry=updated,
        added_entries=max(0, len(updated.entries) - before),
    )
