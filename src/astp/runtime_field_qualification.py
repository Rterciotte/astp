from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class QualificationCheck(StrEnum):
    PERMIT_BEFORE_IO = "permit-before-io"
    NETWORK_WITHOUT_PERMIT_REJECTED = "network-without-permit-rejected"
    SHELL_REJECTED = "shell-rejected"
    SIGNING_KEYS_ABSENT = "signing-keys-absent"
    BOUNDED_OUTPUT = "bounded-output"
    FIELD_TEST_COMPLETED = "field-test-completed"
    ARTIFACT_DIGEST_MATCHED = "artifact-digest-matched"
    RECEIPT_INGESTION_VERIFIED = "receipt-ingestion-verified"


_REQUIRED_CHECKS = frozenset(item.value for item in QualificationCheck)


class RuntimeFieldAssertion(BaseModel):
    model_config = ConfigDict(frozen=True)

    check: QualificationCheck
    passed: bool
    evidence_ref: str


class RuntimeFieldQualification(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    artifact_digest: str
    test_environment: str
    assertions: tuple[RuntimeFieldAssertion, ...] = Field(default_factory=tuple)
    authorized_field_test: bool = False

    def qualification_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class RuntimeFieldQualificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    qualified: bool
    qualification_hash: str
    passed_checks: tuple[str, ...]
    missing_checks: tuple[str, ...]
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_runtime_field_qualification(
    record: RuntimeFieldQualification,
) -> RuntimeFieldQualificationResult:
    if not record.artifact_digest.startswith("sha256:"):
        raise ValueError("runtime field qualification requires a sha256 artifact digest")
    passed = {
        assertion.check.value
        for assertion in record.assertions
        if assertion.passed and assertion.evidence_ref.strip()
    }
    missing = tuple(sorted(_REQUIRED_CHECKS - passed))
    reasons: list[str] = []
    if missing:
        reasons.append("required runtime qualification checks are incomplete")
    if not record.authorized_field_test:
        reasons.append("authorized field test has not been recorded")
    return RuntimeFieldQualificationResult(
        runtime_id=record.runtime_id,
        qualified=not missing and record.authorized_field_test,
        qualification_hash=record.qualification_hash(),
        passed_checks=tuple(sorted(passed)),
        missing_checks=missing,
        reasons=tuple(reasons),
    )
