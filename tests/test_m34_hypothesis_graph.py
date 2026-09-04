from datetime import UTC, datetime

from astp.hypothesis import build_observation_hypotheses
from astp.security_graph import GraphNodeKind, SecurityGraph, SecurityGraphNode


def test_hypothesis_requires_policy_and_permit() -> None:
    graph = SecurityGraph(
        engagement_id="e",
        created_at=datetime.now(UTC),
        nodes=[
            SecurityGraphNode(
                id="asset-1",
                kind=GraphNodeKind.ASSET,
                label="https://example.com/",
                attributes={"in_scope": "true"},
            )
        ],
    )
    result = build_observation_hypotheses(graph)
    assert len(result.hypotheses) == 1
    hypothesis = result.hypotheses[0]
    assert hypothesis.requires_policy_evaluation is True
    assert hypothesis.requires_execution_permit is True
