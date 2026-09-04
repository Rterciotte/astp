from datetime import UTC, datetime

from astp.security_graph import GraphNodeKind, build_security_graph
from astp.target_discovery import (
    CandidateKind,
    CandidateSafety,
    DiscoveryProvenance,
    TargetCandidate,
)
from astp.target_registry import RegistryEntry, TargetRegistry


def test_graph_preserves_target_evidence_action_provenance() -> None:
    now = datetime.now(UTC)
    provenance = DiscoveryProvenance(
        evidence_id="ev",
        source_action_id="act",
        source_target="https://example.com/",
        source_kind=CandidateKind.REDIRECT,
        observed_at=now,
    )
    candidate = TargetCandidate(
        id="c",
        canonical_target="https://www.example.com/",
        display_target="https://www.example.com/",
        kind=CandidateKind.REDIRECT,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        reason="ok",
        provenance=(provenance,),
        discovered_at=now,
    )
    registry = TargetRegistry(
        engagement_id="e",
        updated_at=now,
        entries=[
            RegistryEntry(
                canonical_target=candidate.canonical_target,
                candidate_ids=["c"],
                provenance=[provenance],
                latest_candidate=candidate,
                first_seen_at=now,
                last_seen_at=now,
            )
        ],
    )
    graph = build_security_graph(registry)
    assert {node.kind for node in graph.nodes} == {
        GraphNodeKind.ASSET,
        GraphNodeKind.EVIDENCE,
        GraphNodeKind.ACTION,
    }
    assert len(graph.edges) == 2
