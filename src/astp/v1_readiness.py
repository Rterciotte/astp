from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class V1Readiness(BaseModel):
    model_config = ConfigDict(frozen=True)

    architecture_complete: bool
    offline_end_to_end_rehearsal: bool
    runtime_field_qualification_complete: bool
    broad_active_verification_field_qualified: bool
    authorized_e2e_field_test_complete: bool
    full_pentest_ready: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_v1_readiness(
    *,
    runtime_field_qualification_complete: bool = False,
    broad_active_verification_field_qualified: bool = False,
    authorized_e2e_field_test_complete: bool = False,
) -> V1Readiness:
    blockers: list[str] = []
    if not runtime_field_qualification_complete:
        blockers.append("runtime field qualification is incomplete")
    if not broad_active_verification_field_qualified:
        blockers.append("broad active verification is not field-qualified")
    if not authorized_e2e_field_test_complete:
        blockers.append("authorized end-to-end assessment field test is incomplete")
    ready = not blockers
    return V1Readiness(
        architecture_complete=True,
        offline_end_to_end_rehearsal=True,
        runtime_field_qualification_complete=runtime_field_qualification_complete,
        broad_active_verification_field_qualified=broad_active_verification_field_qualified,
        authorized_e2e_field_test_complete=authorized_e2e_field_test_complete,
        full_pentest_ready=ready,
        blockers=tuple(blockers),
    )
