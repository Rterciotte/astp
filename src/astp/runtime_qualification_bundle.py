from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_qualification_record import RuntimeQualificationRecord
from astp.runtime_specs import RuntimeSpec


class RuntimeQualificationAssertion(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    evidence_ref: str


class RuntimeQualificationBundle(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    artifact_digest: str
    field_test_name: str
    assertions: tuple[RuntimeQualificationAssertion, ...] = Field(default_factory=tuple)

    def bundle_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


_REQUIRED = {
    "permit-before-io",
    "network-without-permit-rejected",
    "shell-rejected",
    "signing-keys-absent",
    "bounded-output",
    "field-test-completed",
}


def qualify_runtime_bundle(
    spec: RuntimeSpec,
    bundle: RuntimeQualificationBundle,
) -> RuntimeQualificationRecord:
    if bundle.runtime_id != spec.id:
        raise ValueError("qualification bundle runtime_id does not match runtime specification")
    if not bundle.artifact_digest.startswith("sha256:"):
        raise ValueError("runtime qualification requires a sha256 artifact digest")
    passed = {item.name for item in bundle.assertions if item.passed and item.evidence_ref.strip()}
    qualified = _REQUIRED.issubset(passed)
    return RuntimeQualificationRecord(
        runtime_id=bundle.runtime_id,
        artifact_digest=bundle.artifact_digest,
        qualified=qualified,
        field_test_name=bundle.field_test_name if qualified else None,
        checks=tuple(sorted(passed)),
    )
