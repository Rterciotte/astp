from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field

from astp.qualification_session import (
    QualificationProbe,
    QualificationProbeResult,
    RuntimeQualificationSession,
    evaluate_qualification_session,
)


class PhysicalProbeObservation(BaseModel):
    model_config = ConfigDict(frozen=True)
    probe: QualificationProbe
    passed: bool
    command_digest: str
    output_digest: str
    note: str = ""


class PhysicalQualificationRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    runtime_id: str
    image_digest: str
    engagement_id: str
    authorized_lab: bool
    observations: tuple[PhysicalProbeObservation, ...] = Field(default_factory=tuple)

    def record_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_session(self) -> RuntimeQualificationSession:
        probes = tuple(
            QualificationProbeResult(
                probe=o.probe,
                passed=o.passed,
                evidence_ref=f"physical:{self.record_hash()}:{o.probe.value}:{o.output_digest}",
            )
            for o in self.observations
        )
        return RuntimeQualificationSession(
            runtime_id=self.runtime_id,
            image_digest=self.image_digest,
            engagement_id=self.engagement_id,
            authorized_lab=self.authorized_lab,
            probes=probes,
        )


def evaluate_physical_record(record: PhysicalQualificationRecord):
    return evaluate_qualification_session(record.to_session())
