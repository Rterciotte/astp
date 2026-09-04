from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from astp.io import dump_yaml, load_model
from astp.target_discovery import DiscoveryProvenance, TargetCandidate, TargetDiscoveryResult


class RegistryEntry(BaseModel):
    canonical_target: str
    candidate_ids: list[str] = Field(default_factory=list)
    provenance: list[DiscoveryProvenance] = Field(default_factory=list)
    latest_candidate: TargetCandidate
    first_seen_at: datetime
    last_seen_at: datetime


class TargetRegistry(BaseModel):
    schema_version: str = "1"
    engagement_id: str
    entries: list[RegistryEntry] = Field(default_factory=list)
    updated_at: datetime


def empty_registry(engagement_id: str, *, now: datetime | None = None) -> TargetRegistry:
    return TargetRegistry(
        engagement_id=engagement_id,
        entries=[],
        updated_at=now or datetime.now(UTC),
    )


def merge_discovery(
    registry: TargetRegistry,
    discovery: TargetDiscoveryResult,
    *,
    now: datetime | None = None,
) -> TargetRegistry:
    current = now or datetime.now(UTC)
    by_target = {entry.canonical_target: entry for entry in registry.entries}
    for candidate in discovery.candidates:
        if candidate.canonical_target is None:
            continue
        entry = by_target.get(candidate.canonical_target)
        if entry is None:
            entry = RegistryEntry(
                canonical_target=candidate.canonical_target,
                candidate_ids=[candidate.id],
                provenance=list(candidate.provenance),
                latest_candidate=candidate,
                first_seen_at=candidate.discovered_at,
                last_seen_at=candidate.discovered_at,
            )
            registry.entries.append(entry)
            by_target[candidate.canonical_target] = entry
        else:
            if candidate.id not in entry.candidate_ids:
                entry.candidate_ids.append(candidate.id)
            known = {
                (item.evidence_id, item.source_action_id, item.source_kind.value)
                for item in entry.provenance
            }
            for provenance in candidate.provenance:
                key = (
                    provenance.evidence_id,
                    provenance.source_action_id,
                    provenance.source_kind.value,
                )
                if key not in known:
                    entry.provenance.append(provenance)
                    known.add(key)
            entry.latest_candidate = candidate
            entry.last_seen_at = max(entry.last_seen_at, candidate.discovered_at)
    registry.entries.sort(key=lambda item: item.canonical_target)
    registry.updated_at = current
    return registry


def load_or_create_registry(path: Path, engagement_id: str) -> TargetRegistry:
    if path.exists():
        registry = load_model(path, TargetRegistry)
        if registry.engagement_id != engagement_id:
            raise ValueError("Target registry belongs to a different engagement.")
        return registry
    return empty_registry(engagement_id)


def save_registry(registry: TargetRegistry, path: Path) -> None:
    dump_yaml(registry, path)
