from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_qualification import RuntimeQualificationResult


class RuntimeQualificationRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    artifact_digest: str
    qualified: bool
    field_test_name: str | None = None
    checks: tuple[str, ...] = Field(default_factory=tuple)


def build_qualification_record(
    result: RuntimeQualificationResult,
    *,
    artifact_digest: str,
    field_test_name: str | None,
) -> RuntimeQualificationRecord:
    return RuntimeQualificationRecord(
        runtime_id=result.runtime_id,
        artifact_digest=artifact_digest,
        qualified=result.qualified,
        field_test_name=field_test_name,
        checks=result.checks_passed,
    )
