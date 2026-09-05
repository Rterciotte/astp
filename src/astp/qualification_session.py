from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class QualificationProbe(StrEnum):
    IMAGE_DIGEST = "image-digest"
    READ_ONLY_ROOT = "read-only-root"
    NO_NEW_PRIVILEGES = "no-new-privileges"
    SHELL_REJECTED = "shell-rejected"
    SIGNING_KEYS_ABSENT = "signing-keys-absent"
    NETWORK_WITHOUT_PERMIT_REJECTED = "network-without-permit-rejected"
    PERMIT_BEFORE_IO = "permit-before-io"
    BOUNDED_OUTPUT = "bounded-output"
    RECEIPT_INGESTION = "receipt-ingestion"


class QualificationProbeResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    probe: QualificationProbe
    passed: bool
    evidence_ref: str


class RuntimeQualificationSession(BaseModel):
    model_config = ConfigDict(frozen=True)
    runtime_id: str
    image_digest: str
    engagement_id: str
    authorized_lab: bool = False
    probes: tuple[QualificationProbeResult, ...] = Field(default_factory=tuple)

    def session_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()


class QualificationSessionDecision(BaseModel):
    model_config = ConfigDict(frozen=True)
    qualified: bool
    session_hash: str
    missing_probes: tuple[str, ...]
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_qualification_session(
    session: RuntimeQualificationSession,
) -> QualificationSessionDecision:
    required = {item.value for item in QualificationProbe}
    passed = {
        item.probe.value for item in session.probes if item.passed and item.evidence_ref.strip()
    }
    missing = tuple(sorted(required - passed))
    reasons: list[str] = []
    if not session.authorized_lab:
        reasons.append("qualification session is not bound to an authorized lab")
    if missing:
        reasons.append("runtime qualification probes are incomplete")
    if not session.image_digest.startswith("sha256:"):
        reasons.append("qualification image digest is not sha256-bound")
    return QualificationSessionDecision(
        qualified=not reasons,
        session_hash=session.session_hash(),
        missing_probes=missing,
        reasons=tuple(reasons),
    )
