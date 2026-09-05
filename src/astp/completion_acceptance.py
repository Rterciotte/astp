from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_progress import RuntimeProgress


class FullPentestAcceptance(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_qualification_complete: bool
    broad_active_verification_complete: bool
    adaptive_loop_field_tested: bool
    state_change_operator_path_field_tested: bool
    authorized_end_to_end_field_tested: bool
    accepted: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_full_pentest_acceptance(
    runtime_progress: RuntimeProgress,
    *,
    broad_active_verification_complete: bool,
    adaptive_loop_field_tested: bool,
    state_change_operator_path_field_tested: bool,
    authorized_end_to_end_field_tested: bool,
) -> FullPentestAcceptance:
    runtime_complete = runtime_progress.qualified_runtimes == runtime_progress.total_runtimes
    blockers: list[str] = []
    if not runtime_complete:
        blockers.append("all isolated runtimes must be field-qualified")
    if not broad_active_verification_complete:
        blockers.append("broad vulnerability-specific active verification is incomplete")
    if not adaptive_loop_field_tested:
        blockers.append("adaptive coordinator loop is not field-tested")
    if not state_change_operator_path_field_tested:
        blockers.append("operator-gated state-changing path is not field-tested")
    if not authorized_end_to_end_field_tested:
        blockers.append("authorized end-to-end assessment has not been field-tested")
    return FullPentestAcceptance(
        runtime_qualification_complete=runtime_complete,
        broad_active_verification_complete=broad_active_verification_complete,
        adaptive_loop_field_tested=adaptive_loop_field_tested,
        state_change_operator_path_field_tested=state_change_operator_path_field_tested,
        authorized_end_to_end_field_tested=authorized_end_to_end_field_tested,
        accepted=not blockers,
        blockers=tuple(blockers),
    )
