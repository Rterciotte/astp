from datetime import UTC, datetime

from astp.surface_mapper import build_surface_map
from astp.target_discovery import CandidateKind, CandidateSafety, TargetCandidate
from astp.target_registry import RegistryEntry, TargetRegistry


def candidate(target, id):
    return TargetCandidate(
        id=id,
        canonical_target=target,
        display_target=target,
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        reason="ok",
        provenance=(),
        discovered_at=datetime.now(UTC),
    )


def test_surface_map_dedupes_query_values_but_keeps_keys():
    now = datetime.now(UTC)
    c1 = candidate("https://example.com/a?id=1", "c1")
    c2 = candidate("https://example.com/a?id=2", "c2")
    reg = TargetRegistry(
        engagement_id="e",
        updated_at=now,
        entries=[
            RegistryEntry(
                canonical_target=c1.canonical_target,
                candidate_ids=["c1"],
                latest_candidate=c1,
                first_seen_at=now,
                last_seen_at=now,
            ),
            RegistryEntry(
                canonical_target=c2.canonical_target,
                candidate_ids=["c2"],
                latest_candidate=c2,
                first_seen_at=now,
                last_seen_at=now,
            ),
        ],
    )
    result = build_surface_map(reg)
    assert len(result.endpoints) == 1
    assert result.endpoints[0].query_keys == ["id"]
