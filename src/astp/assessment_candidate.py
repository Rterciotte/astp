from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_enablement import candidate_runtime_enablement


class AutonomousAssessmentCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    safe_http_observation: bool = True
    dns_tls_observation: bool = True
    authenticated_http: bool = True
    browser_boundary: bool = True
    external_tool_boundary: bool = True
    evidence_feedback: bool = True
    report_bundle: bool = True
    runtime_field_qualification_complete: bool = False
    broad_active_verification_complete: bool = False
    authorized_end_to_end_field_test: bool = False
    full_pentest_ready: bool = False
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def current_autonomous_assessment_candidate() -> AutonomousAssessmentCandidate:
    runtimes = candidate_runtime_enablement()
    runtime_complete = all(item.operational_ready for item in runtimes)
    blockers: list[str] = []
    if not runtime_complete:
        blockers.append("isolated runtimes are bundled but not field-qualified")
    blockers.append("broad vulnerability-specific active verification is incomplete")
    blockers.append("authorized end-to-end assessment field test has not been recorded")
    return AutonomousAssessmentCandidate(
        runtime_field_qualification_complete=runtime_complete,
        blockers=tuple(blockers),
    )
