from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from astp.fingerprint import TechnologyFingerprint
from astp.protocol_analyzers import ProtocolAnalysis
from astp.web_posture import WebPostureAssessment


class NormalizedSignalClass(str, Enum):
    TECHNOLOGY = "technology"
    POSTURE = "posture"
    SECURITY_REVIEW = "security_review"


class NormalizedSignal(BaseModel):
    key: str
    signal_class: NormalizedSignalClass
    target: str
    observation: str
    evidence_id: str
    confidence: float = Field(ge=0, le=1)
    eligible_for_finding_candidate: bool = False
    confirmed_vulnerability: bool = False


def normalize_signals(
    fingerprint: TechnologyFingerprint,
    protocol: ProtocolAnalysis,
    posture: WebPostureAssessment | None = None,
) -> list[NormalizedSignal]:
    rows: list[NormalizedSignal] = []
    for item in fingerprint.observations:
        rows.append(
            NormalizedSignal(
                key=f"fingerprint.{item.kind.value}.{item.value.lower()}",
                signal_class=NormalizedSignalClass.TECHNOLOGY,
                target=fingerprint.target,
                observation=f"{item.kind.value}: {item.value}",
                evidence_id=item.evidence_id,
                confidence=item.confidence,
            )
        )
    for item in protocol.signals:
        rows.append(
            NormalizedSignal(
                key=f"protocol.{item.name}",
                signal_class=(
                    NormalizedSignalClass.POSTURE
                    if item.informational_only
                    else NormalizedSignalClass.SECURITY_REVIEW
                ),
                target=protocol.target,
                observation=item.observation,
                evidence_id=item.evidence_id,
                confidence=item.confidence,
                eligible_for_finding_candidate=not item.informational_only,
                confirmed_vulnerability=item.confirmed_vulnerability,
            )
        )
    if posture is not None:
        for item in posture.signals:
            rows.append(
                NormalizedSignal(
                    key=f"posture.{item.name}",
                    signal_class=NormalizedSignalClass.POSTURE,
                    target=posture.target,
                    observation=item.observation,
                    evidence_id=item.evidence_id,
                    confidence=0.7,
                    confirmed_vulnerability=item.vulnerability_confirmed,
                )
            )
    return rows
