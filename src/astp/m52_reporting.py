from __future__ import annotations

from pydantic import BaseModel, Field

from astp.detector_policy import DetectorPolicyDecision
from astp.proof_model import DetectorProof, ProofStateV2


class DetectionCoverage(BaseModel):
    detector_id: str
    selected: bool
    decision: DetectorPolicyDecision
    targets: tuple[str, ...] = ()
    requests: int = 0
    evidence_ids: tuple[str, ...] = ()


class M52ReportInput(BaseModel):
    coverage: list[DetectionCoverage] = Field(default_factory=list)
    proofs: list[DetectorProof] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def render_detection_report(data: M52ReportInput) -> str:
    confirmed = [
        proof
        for proof in data.proofs
        if proof.state in {ProofStateV2.CONFIRMED, ProofStateV2.IMPACT_DEMONSTRATED}
    ]
    lines = [
        "# ASTP Vulnerability Detection Report",
        "",
        "## Executive summary",
        "",
        f"Confirmed findings: {len(confirmed)}",
        f"Detector decisions: {len(data.coverage)}",
        "",
        "## Coverage executed",
        "",
    ]
    for row in data.coverage:
        status = "executed" if row.selected else f"skipped ({row.decision.code.value})"
        lines.append(
            f"- `{row.detector_id}`: {status}; targets={len(row.targets)}; requests={row.requests}; evidence={len(row.evidence_ids)}"
        )
    if not data.coverage:
        lines.append("- No detectors were eligible or executed.")
    lines.extend(["", "## Proofs", ""])
    for proof in data.proofs:
        lines.append(
            f"- `{proof.vulnerability_family.value}`: **{proof.state.value}**, confidence {proof.confidence:.2f}; tool `{proof.tool_id}` {proof.tool_version}; evidence {', '.join(proof.evidence_ids) or 'none'}"
        )
    if not data.proofs:
        lines.append("- No finding candidates were produced.")
    lines.extend(["", "## Limitations", ""])
    lines.extend([f"- {item}" for item in data.limitations] or ["- None recorded."])
    return "\n".join(lines) + "\n"
