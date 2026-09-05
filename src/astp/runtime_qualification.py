from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_specs import RuntimeSpec, builtin_runtime_specs


class RuntimeQualificationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    artifact_digest: str
    version_reported: str
    permit_consumed_before_io_tested: bool = False
    network_without_permit_rejected: bool = False
    arbitrary_shell_rejected: bool = False
    signing_keys_absent: bool = False
    output_bound_tested: bool = False
    field_test_name: str | None = None


class RuntimeQualificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    qualified: bool
    checks_passed: tuple[str, ...] = Field(default_factory=tuple)
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def qualify_runtime(
    spec: RuntimeSpec,
    evidence: RuntimeQualificationEvidence,
) -> RuntimeQualificationResult:
    if evidence.runtime_id != spec.id:
        return RuntimeQualificationResult(
            runtime_id=spec.id,
            qualified=False,
            blockers=("qualification evidence is bound to a different runtime id",),
        )
    checks: list[str] = []
    blockers: list[str] = []
    required = {
        "artifact digest recorded": bool(evidence.artifact_digest.strip()),
        "runtime version recorded": bool(evidence.version_reported.strip()),
        "permit consumed before I/O": evidence.permit_consumed_before_io_tested,
        "network without permit rejected": evidence.network_without_permit_rejected,
        "arbitrary shell rejected": evidence.arbitrary_shell_rejected,
        "signing keys absent": evidence.signing_keys_absent,
        "bounded output tested": evidence.output_bound_tested,
        "field test recorded": bool(evidence.field_test_name),
    }
    for label, passed in required.items():
        (checks if passed else blockers).append(label)
    return RuntimeQualificationResult(
        runtime_id=spec.id,
        qualified=not blockers,
        checks_passed=tuple(checks),
        blockers=tuple(blockers),
    )


def qualification_template(runtime_id: str) -> RuntimeQualificationEvidence:
    known = {item.id for item in builtin_runtime_specs()}
    if runtime_id not in known:
        raise ValueError(f"unknown runtime id: {runtime_id}")
    return RuntimeQualificationEvidence(
        runtime_id=runtime_id,
        artifact_digest="",
        version_reported="",
    )
