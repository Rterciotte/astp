from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_qualification import RuntimeQualificationResult
from astp.verifier_readiness import VerifierFamilyReadiness


class CompletionReadiness(BaseModel):
    model_config = ConfigDict(frozen=True)

    qualified_runtimes: int
    total_runtimes: int
    qualified_verifier_families: int
    total_verifier_families: int
    full_runtime_ready: bool
    broad_verification_ready: bool
    full_pentest_ready: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_completion_readiness(
    runtime_results: tuple[RuntimeQualificationResult, ...],
    verifier_rows: tuple[VerifierFamilyReadiness, ...],
    *,
    state_changing_operator_path_field_tested: bool = False,
) -> CompletionReadiness:
    qualified_runtimes = sum(1 for item in runtime_results if item.qualified)
    qualified_families = sum(1 for item in verifier_rows if item.operationally_qualified)
    full_runtime = bool(runtime_results) and qualified_runtimes == len(runtime_results)
    broad_verification = bool(verifier_rows) and qualified_families == len(verifier_rows)
    blockers: list[str] = []
    if not full_runtime:
        blockers.append("all required worker runtimes must be field-qualified")
    if not broad_verification:
        blockers.append("all verifier families must have operational qualification")
    if not state_changing_operator_path_field_tested:
        blockers.append("operator-gated state-changing path is not field-tested end-to-end")
    return CompletionReadiness(
        qualified_runtimes=qualified_runtimes,
        total_runtimes=len(runtime_results),
        qualified_verifier_families=qualified_families,
        total_verifier_families=len(verifier_rows),
        full_runtime_ready=full_runtime,
        broad_verification_ready=broad_verification,
        full_pentest_ready=not blockers,
        blockers=tuple(blockers),
    )
