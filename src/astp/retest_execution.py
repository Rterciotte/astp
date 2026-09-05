from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from astp.retest_scheduler import RetestRequest
from astp.safe_verification_executor import SafeVerificationResult


class RetestOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding_id: str
    verification_envelope_id: str
    evidence_id: str | None
    completed: bool
    resolved: bool | None = None
    requires_human_resolution: bool = True


def build_retest_outcome(
    request: RetestRequest,
    verification: SafeVerificationResult,
) -> RetestOutcome:
    return RetestOutcome(
        finding_id=request.finding_id,
        verification_envelope_id=verification.envelope_id,
        evidence_id=verification.evidence_id,
        completed=verification.status.value == "completed",
    )
