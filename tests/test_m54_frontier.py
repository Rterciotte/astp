from datetime import UTC, datetime

from astp.frontier import FrontierState, build_frontier, mark_frontier_visited
from astp.target_discovery import (
    CandidateKind,
    CandidateSafety,
    DiscoveryProvenance,
    TargetCandidate,
)
from astp.target_registry import RegistryEntry, TargetRegistry


def test_frontier_tracks_visit_state():
    now = datetime.now(UTC)
    provenance = DiscoveryProvenance(
        evidence_id="e",
        source_action_id="a",
        source_target="https://example.com/start",
        source_kind=CandidateKind.REDIRECT,
        observed_at=now,
    )
    candidate = TargetCandidate(
        id="t",
        canonical_target="https://example.com/",
        display_target="https://example.com/",
        kind=CandidateKind.REDIRECT,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        same_origin=True,
        reason="test",
        provenance=(provenance,),
        discovered_at=now,
    )
    registry = TargetRegistry(
        engagement_id="e",
        updated_at=now,
        entries=[
            RegistryEntry(
                canonical_target="https://example.com/",
                candidate_ids=["t"],
                provenance=[provenance],
                latest_candidate=candidate,
                first_seen_at=now,
                last_seen_at=now,
            )
        ],
    )
    frontier = build_frontier(registry, max_depth=2)
    assert frontier.items[0].state == FrontierState.READY
    assert mark_frontier_visited(frontier, "t").items[0].state == FrontierState.VISITED
