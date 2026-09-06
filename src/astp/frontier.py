from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.target_registry import TargetRegistry


class FrontierState(str, Enum):
    READY = "ready"
    VISITED = "visited"
    BLOCKED = "blocked"


class FrontierItem(BaseModel):
    target_id: str
    target: str
    depth: int = Field(ge=0)
    state: FrontierState = FrontierState.READY
    parent_target_id: str | None = None


class CrawlFrontier(BaseModel):
    schema_version: str = "1"
    created_at: datetime
    max_depth: int
    items: list[FrontierItem] = Field(default_factory=list)


def build_frontier(registry: TargetRegistry, *, max_depth: int = 3) -> CrawlFrontier:
    if max_depth < 0:
        raise ValueError("max_depth cannot be negative")
    items = [
        FrontierItem(target_id=entry.latest_candidate.id, target=entry.canonical_target, depth=0)
        for entry in registry.entries
        if entry.latest_candidate.in_scope
    ]
    return CrawlFrontier(
        created_at=datetime.now(UTC),
        max_depth=max_depth,
        items=items,
    )


def mark_frontier_visited(frontier: CrawlFrontier, target_id: str) -> CrawlFrontier:
    found = False
    rows: list[FrontierItem] = []
    for item in frontier.items:
        if item.target_id == target_id:
            found = True
            rows.append(item.model_copy(update={"state": FrontierState.VISITED}))
        else:
            rows.append(item)
    if not found:
        raise ValueError(f"unknown frontier target: {target_id}")
    return frontier.model_copy(update={"items": rows})
