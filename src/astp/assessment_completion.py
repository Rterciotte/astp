from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from astp.pentest_readiness import PentestReadiness, current_pentest_readiness


class PentestCompletionAssessment(BaseModel):
    model_config = ConfigDict(frozen=True)

    complete_end_to_end: bool
    safe_observation_end_to_end: bool
    authenticated_observation_end_to_end: bool
    blockers: tuple[str, ...]


def evaluate_pentest_completion() -> PentestCompletionAssessment:
    readiness: PentestReadiness = current_pentest_readiness()
    return PentestCompletionAssessment(
        complete_end_to_end=readiness.full_pentest_ready,
        safe_observation_end_to_end=True,
        authenticated_observation_end_to_end=readiness.authenticated_session_execution,
        blockers=tuple(readiness.blockers),
    )
