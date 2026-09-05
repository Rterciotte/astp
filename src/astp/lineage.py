from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from astp.assessment import AssessmentResult


class LineageNodeKind(str, Enum):
    EVIDENCE = "evidence"
    SIGNAL = "signal"
    FINDING = "finding"
    REPORT = "report"


class LineageNode(BaseModel):
    id: str
    kind: LineageNodeKind
    label: str


class LineageEdge(BaseModel):
    source: str
    target: str
    relation: str


class AssessmentLineage(BaseModel):
    schema_version: str = "1"
    nodes: list[LineageNode] = Field(default_factory=list)
    edges: list[LineageEdge] = Field(default_factory=list)


def build_assessment_lineage(result: AssessmentResult) -> AssessmentLineage:
    nodes: dict[str, LineageNode] = {}
    edges: set[tuple[str, str, str]] = set()
    for fingerprint in result.fingerprints:
        for evidence_id in fingerprint.evidence_ids:
            nodes.setdefault(
                evidence_id,
                LineageNode(id=evidence_id, kind=LineageNodeKind.EVIDENCE, label=evidence_id),
            )
    for signal in result.signals:
        signal_id = f"signal:{signal.key}:{signal.evidence_id}"
        nodes[signal_id] = LineageNode(
            id=signal_id,
            kind=LineageNodeKind.SIGNAL,
            label=signal.key,
        )
        nodes.setdefault(
            signal.evidence_id,
            LineageNode(
                id=signal.evidence_id,
                kind=LineageNodeKind.EVIDENCE,
                label=signal.evidence_id,
            ),
        )
        edges.add((signal.evidence_id, signal_id, "supports"))
    for finding in result.findings.findings:
        nodes[finding.id] = LineageNode(
            id=finding.id,
            kind=LineageNodeKind.FINDING,
            label=finding.vulnerability,
        )
        for signal in finding.signals:
            signal_id = f"signal:{signal.sensor}:{signal.evidence_id}"
            nodes.setdefault(
                signal_id,
                LineageNode(id=signal_id, kind=LineageNodeKind.SIGNAL, label=signal.sensor),
            )
            edges.add((signal_id, finding.id, "correlates_to"))
    report_id = f"report:{result.session_id}"
    nodes[report_id] = LineageNode(
        id=report_id,
        kind=LineageNodeKind.REPORT,
        label="assessment report",
    )
    for finding in result.findings.findings:
        edges.add((finding.id, report_id, "included_in"))
    return AssessmentLineage(
        nodes=sorted(nodes.values(), key=lambda node: node.id),
        edges=[LineageEdge(source=a, target=b, relation=c) for a, b, c in sorted(edges)],
    )
