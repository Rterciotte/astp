from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from astp.assessment import AssessmentResult


class AssessmentManifest(BaseModel):
    schema_version: str = "1"
    session_id: str
    created_at: datetime
    evidence_ids: list[str] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    invalid_evidence_ids: list[str] = Field(default_factory=list)
    report_sha256: str
    manifest_hash: str


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


def build_assessment_manifest(result: AssessmentResult) -> AssessmentManifest:
    evidence_ids = sorted(
        {
            evidence_id
            for fingerprint in result.fingerprints
            for evidence_id in fingerprint.evidence_ids
        }
    )
    manifest = AssessmentManifest(
        session_id=result.session_id,
        created_at=datetime.now(UTC),
        evidence_ids=evidence_ids,
        finding_ids=sorted(finding.id for finding in result.findings.findings),
        invalid_evidence_ids=sorted(result.invalid_evidence_ids),
        report_sha256=hashlib.sha256(result.report_markdown.encode()).hexdigest(),
        manifest_hash="pending",
    )
    payload = manifest.model_dump(mode="json", exclude={"manifest_hash"})
    digest = hashlib.sha256(_canonical(payload)).hexdigest()
    return manifest.model_copy(update={"manifest_hash": digest})


def verify_assessment_manifest(manifest: AssessmentManifest) -> bool:
    payload = manifest.model_dump(mode="json", exclude={"manifest_hash"})
    return hashlib.sha256(_canonical(payload)).hexdigest() == manifest.manifest_hash
