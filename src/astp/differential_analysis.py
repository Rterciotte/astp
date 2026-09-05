from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict

from astp.observation import HttpObservationEvidence


class DifferentialComparison(BaseModel):
    model_config = ConfigDict(frozen=True)

    baseline_evidence_id: str
    comparison_evidence_id: str
    same_status: bool
    same_body_hash: bool
    same_content_type: bool
    body_preview_equal: bool
    authorization_boundary_signal: bool
    confidence: float
    rationale: tuple[str, ...]


def compare_authorization_evidence(
    baseline: HttpObservationEvidence,
    comparison: HttpObservationEvidence,
) -> DifferentialComparison:
    if baseline.target != comparison.target:
        raise ValueError("authorization differential evidence must target the same resource")
    if baseline.method != comparison.method:
        raise ValueError("authorization differential evidence must use the same method")

    same_status = baseline.status_code == comparison.status_code
    same_body_hash = baseline.body_sha256 == comparison.body_sha256
    same_content_type = baseline.content_type == comparison.content_type
    body_preview_equal = baseline.body_preview == comparison.body_preview

    rationale: list[str] = []
    score = 0.0
    if same_status and baseline.status_code < 400:
        score += 0.35
        rationale.append("both identities received a non-error status")
    if same_body_hash:
        score += 0.45
        rationale.append("response body hashes are identical")
    elif body_preview_equal and baseline.body_preview is not None:
        score += 0.25
        rationale.append("captured response previews are identical")
    if same_content_type:
        score += 0.10
        rationale.append("response content types match")

    signal = score >= 0.70
    if not signal:
        rationale.append("evidence is insufficient to claim an authorization boundary issue")
    return DifferentialComparison(
        baseline_evidence_id=baseline.evidence_id,
        comparison_evidence_id=comparison.evidence_id,
        same_status=same_status,
        same_body_hash=same_body_hash,
        same_content_type=same_content_type,
        body_preview_equal=body_preview_equal,
        authorization_boundary_signal=signal,
        confidence=round(min(score, 1.0), 2),
        rationale=tuple(rationale),
    )


def comparison_id(comparison: DifferentialComparison) -> str:
    raw = f"{comparison.baseline_evidence_id}|{comparison.comparison_evidence_id}"
    return f"authzcmp-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"
