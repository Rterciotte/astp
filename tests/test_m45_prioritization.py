from datetime import UTC, datetime

from astp.prioritization import prioritize_registry
from astp.target_discovery import CandidateKind, CandidateSafety, TargetCandidate
from astp.target_registry import RegistryEntry, TargetRegistry


def make(target, same, id):
    now = datetime.now(UTC)
    c = TargetCandidate(
        id=id,
        canonical_target=target,
        display_target=target,
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        same_origin=same,
        reason="ok",
        provenance=(),
        discovered_at=now,
    )
    return RegistryEntry(
        canonical_target=target,
        candidate_ids=[id],
        latest_candidate=c,
        first_seen_at=now,
        last_seen_at=now,
    )


def test_same_origin_scores_higher():
    now = datetime.now(UTC)
    reg = TargetRegistry(
        engagement_id="e",
        updated_at=now,
        entries=[
            make("https://example.com/a", False, "a"),
            make("https://example.com/b", True, "b"),
        ],
    )
    rows = prioritize_registry(reg)
    assert rows[0].target.endswith("/b")
