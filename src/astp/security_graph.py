from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.target_registry import TargetRegistry


class GraphNodeKind(str, Enum):
    ASSET = "asset"
    EVIDENCE = "evidence"
    ACTION = "action"


class GraphEdgeKind(str, Enum):
    DISCOVERED_FROM = "discovered_from"
    OBSERVED_BY = "observed_by"
    SUPPORTS = "supports"


class SecurityGraphNode(BaseModel):
    id: str
    kind: GraphNodeKind
    label: str
    attributes: dict[str, str] = Field(default_factory=dict)


class SecurityGraphEdge(BaseModel):
    source: str
    target: str
    kind: GraphEdgeKind
    attributes: dict[str, str] = Field(default_factory=dict)


class SecurityGraph(BaseModel):
    schema_version: str = "1"
    engagement_id: str
    created_at: datetime
    nodes: list[SecurityGraphNode] = Field(default_factory=list)
    edges: list[SecurityGraphEdge] = Field(default_factory=list)


def _asset_id(target: str) -> str:
    return "asset-" + hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]


def build_security_graph(
    registry: TargetRegistry,
    *,
    now: datetime | None = None,
) -> SecurityGraph:
    nodes: dict[str, SecurityGraphNode] = {}
    edges: dict[tuple[str, str, str], SecurityGraphEdge] = {}

    for entry in registry.entries:
        asset_id = _asset_id(entry.canonical_target)
        nodes[asset_id] = SecurityGraphNode(
            id=asset_id,
            kind=GraphNodeKind.ASSET,
            label=entry.canonical_target,
            attributes={
                "safety": entry.latest_candidate.safety.value,
                "in_scope": str(entry.latest_candidate.in_scope).lower(),
            },
        )
        for provenance in entry.provenance:
            evidence_id = f"evidence-{provenance.evidence_id}"
            action_id = f"action-{provenance.source_action_id}"
            nodes.setdefault(
                evidence_id,
                SecurityGraphNode(
                    id=evidence_id,
                    kind=GraphNodeKind.EVIDENCE,
                    label=provenance.evidence_id,
                ),
            )
            nodes.setdefault(
                action_id,
                SecurityGraphNode(
                    id=action_id,
                    kind=GraphNodeKind.ACTION,
                    label=provenance.source_action_id,
                    attributes={"source_target": provenance.source_target},
                ),
            )
            edges[(asset_id, evidence_id, GraphEdgeKind.DISCOVERED_FROM.value)] = SecurityGraphEdge(
                source=asset_id,
                target=evidence_id,
                kind=GraphEdgeKind.DISCOVERED_FROM,
                attributes={"source_kind": provenance.source_kind.value},
            )
            edges[(evidence_id, action_id, GraphEdgeKind.OBSERVED_BY.value)] = SecurityGraphEdge(
                source=evidence_id,
                target=action_id,
                kind=GraphEdgeKind.OBSERVED_BY,
            )

    return SecurityGraph(
        engagement_id=registry.engagement_id,
        created_at=now or datetime.now(UTC),
        nodes=sorted(nodes.values(), key=lambda item: item.id),
        edges=sorted(edges.values(), key=lambda item: (item.source, item.target, item.kind.value)),
    )
