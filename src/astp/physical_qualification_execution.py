from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from astp.physical_build_provenance import PhysicalImageIdentity
from astp.qualification_session import QualificationProbe


class PhysicalExecutionStage(StrEnum):
    BUILD = "build"
    NEGATIVE_PROBES = "negative-probes"
    AUTHORIZED_LAB = "authorized-lab"
    RECEIPT_INGESTION = "receipt-ingestion"


class PhysicalExecutionObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    probe: QualificationProbe
    passed: bool
    stage: PhysicalExecutionStage
    evidence_path: str
    command_digest: str
    output_digest: str


class PhysicalRuntimeQualificationBundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    identity: PhysicalImageIdentity
    engagement_id: str
    authorized_lab: bool = False
    observations: tuple[PhysicalExecutionObservation, ...] = Field(default_factory=tuple)

    def bundle_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()

    def missing_probes(self) -> tuple[str, ...]:
        passed = {
            item.probe for item in self.observations if item.passed and item.evidence_path.strip()
        }
        return tuple(sorted(probe.value for probe in set(QualificationProbe) - passed))

    def qualified(self) -> bool:
        if not self.authorized_lab:
            return False
        if self.identity.image_id == "sha256:" + "0" * 64:
            return False
        return not self.missing_probes()
