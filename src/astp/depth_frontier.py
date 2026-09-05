from __future__ import annotations

from pydantic import BaseModel

from astp.frontier import CrawlFrontier, FrontierItem, FrontierState
from astp.target_discovery import CandidateSafety, TargetCandidate


class FrontierAdmission(BaseModel):
    admitted: bool
    reason: str
    frontier: CrawlFrontier


def admit_candidate(
    frontier: CrawlFrontier,
    candidate: TargetCandidate,
    *,
    parent_target_id: str,
) -> FrontierAdmission:
    parents = [item for item in frontier.items if item.target_id == parent_target_id]
    if not parents:
        raise ValueError("unknown parent frontier target")
    depth = parents[0].depth + 1
    if candidate.safety != CandidateSafety.READY_FOR_POLICY:
        return FrontierAdmission(
            admitted=False, reason="candidate failed safety checks", frontier=frontier
        )
    if depth > frontier.max_depth:
        return FrontierAdmission(
            admitted=False, reason="maximum discovery depth exceeded", frontier=frontier
        )
    if any(item.target == candidate.canonical_target for item in frontier.items):
        return FrontierAdmission(
            admitted=False, reason="target already exists in frontier", frontier=frontier
        )
    updated = frontier.model_copy(deep=True)
    updated.items.append(
        FrontierItem(
            target_id=candidate.id,
            target=candidate.canonical_target or candidate.display_target,
            depth=depth,
            state=FrontierState.READY,
            parent_target_id=parent_target_id,
        )
    )
    return FrontierAdmission(
        admitted=True, reason="candidate admitted for policy evaluation", frontier=updated
    )
