from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.security_graph import GraphNodeKind, SecurityGraph


class HypothesisState(str, Enum):
    OPEN = "open"
    BLOCKED = "blocked"
    SUPPORTED = "supported"
    REJECTED = "rejected"


class Hypothesis(BaseModel):
    id: str
    category: str
    subject_node_id: str
    statement: str
    state: HypothesisState = HypothesisState.OPEN
    evidence_node_ids: list[str] = Field(default_factory=list)
    next_safe_action: str | None = None
    requires_policy_evaluation: bool = True
    requires_execution_permit: bool = True


class HypothesisGraph(BaseModel):
    schema_version: str = "1"
    engagement_id: str
    created_at: datetime
    hypotheses: list[Hypothesis] = Field(default_factory=list)


def build_observation_hypotheses(
    graph: SecurityGraph,
    *,
    now: datetime | None = None,
) -> HypothesisGraph:
    hypotheses: list[Hypothesis] = []
    for node in graph.nodes:
        if node.kind != GraphNodeKind.ASSET:
            continue
        if node.attributes.get("in_scope") != "true":
            continue
        digest = hashlib.sha256(f"http_surface:{node.id}".encode()).hexdigest()[:16]
        hypotheses.append(
            Hypothesis(
                id=f"hyp-{digest}",
                category="surface_observation",
                subject_node_id=node.id,
                statement=(
                    f"The in-scope HTTP asset {node.label} may expose additional "
                    "observable surface."
                ),
                next_safe_action="policy-evaluate a bounded GET/HEAD observation",
                requires_policy_evaluation=True,
                requires_execution_permit=True,
            )
        )
    return HypothesisGraph(
        engagement_id=graph.engagement_id,
        created_at=now or datetime.now(UTC),
        hypotheses=hypotheses,
    )
