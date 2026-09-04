from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field


class ProofState(str, Enum):
    SUSPECTED = "suspected"
    LIKELY = "likely"
    VERIFIED = "verified"
    IMPACT_CONFIRMED = "impact_confirmed"


_PROOF_ORDER = {
    ProofState.SUSPECTED: 0,
    ProofState.LIKELY: 1,
    ProofState.VERIFIED: 2,
    ProofState.IMPACT_CONFIRMED: 3,
}


class FindingSignal(BaseModel):
    sensor: str
    evidence_id: str
    observation: str
    confidence: float = Field(default=0.5, ge=0, le=1)


class FindingCandidate(BaseModel):
    vulnerability: str
    asset: str
    endpoint: str | None = None
    role: str | None = None
    proof_state: ProofState = ProofState.SUSPECTED
    signals: list[FindingSignal] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    remediation: str | None = None


class CorrelatedFinding(BaseModel):
    id: str
    vulnerability: str
    asset: str
    endpoint: str | None = None
    role: str | None = None
    proof_state: ProofState
    signals: list[FindingSignal] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    remediation: str | None = None
    created_at: datetime


class FindingSet(BaseModel):
    schema_version: str = "1"
    findings: list[CorrelatedFinding] = Field(default_factory=list)


def _correlation_key(candidate: FindingCandidate) -> tuple[str, str, str, str]:
    return (
        candidate.vulnerability.strip().lower(),
        candidate.asset.strip().lower(),
        (candidate.endpoint or "").strip().lower(),
        (candidate.role or "").strip().lower(),
    )


def correlate_findings(
    candidates: list[FindingCandidate],
    *,
    now: datetime | None = None,
) -> FindingSet:
    current = now or datetime.now(UTC)
    grouped: dict[tuple[str, str, str, str], list[FindingCandidate]] = {}
    for candidate in candidates:
        grouped.setdefault(_correlation_key(candidate), []).append(candidate)

    findings: list[CorrelatedFinding] = []
    for key, rows in sorted(grouped.items()):
        strongest = max(rows, key=lambda row: _PROOF_ORDER[row.proof_state])
        payload = json.dumps(key, separators=(",", ":")).encode("utf-8")
        finding_id = "finding-" + hashlib.sha256(payload).hexdigest()[:16]
        signals: list[FindingSignal] = []
        signal_keys: set[tuple[str, str, str]] = set()
        cwe: set[str] = set()
        owasp: set[str] = set()
        remediation = None
        for row in rows:
            cwe.update(row.cwe)
            owasp.update(row.owasp)
            remediation = remediation or row.remediation
            for signal in row.signals:
                signal_key = (signal.sensor, signal.evidence_id, signal.observation)
                if signal_key not in signal_keys:
                    signals.append(signal)
                    signal_keys.add(signal_key)
        findings.append(
            CorrelatedFinding(
                id=finding_id,
                vulnerability=strongest.vulnerability,
                asset=strongest.asset,
                endpoint=strongest.endpoint,
                role=strongest.role,
                proof_state=strongest.proof_state,
                signals=signals,
                cwe=sorted(cwe),
                owasp=sorted(owasp),
                remediation=remediation,
                created_at=current,
            )
        )
    return FindingSet(findings=findings)
