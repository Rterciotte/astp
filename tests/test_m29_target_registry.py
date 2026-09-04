from datetime import UTC, datetime

from astp.target_discovery import (
    CandidateKind,
    CandidateSafety,
    DiscoveryProvenance,
    TargetCandidate,
    TargetDiscoveryResult,
)
from astp.target_registry import empty_registry, merge_discovery


def _candidate(candidate_id: str, evidence_id: str) -> TargetCandidate:
    now = datetime.now(UTC)
    return TargetCandidate(
        id=candidate_id,
        canonical_target="https://www.example.com/",
        display_target="https://www.example.com/",
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        reason="ok",
        provenance=(
            DiscoveryProvenance(
                evidence_id=evidence_id,
                source_action_id="a",
                source_target="https://example.com/",
                source_kind=CandidateKind.LINK,
                observed_at=now,
            ),
        ),
        discovered_at=now,
    )


def test_registry_deduplicates_target_and_merges_provenance() -> None:
    registry = empty_registry("e")
    merge_discovery(
        registry,
        TargetDiscoveryResult(source_evidence_id="ev1", candidates=[_candidate("c1", "ev1")]),
    )
    merge_discovery(
        registry,
        TargetDiscoveryResult(source_evidence_id="ev2", candidates=[_candidate("c2", "ev2")]),
    )
    assert len(registry.entries) == 1
    assert registry.entries[0].candidate_ids == ["c1", "c2"]
    assert len(registry.entries[0].provenance) == 2
