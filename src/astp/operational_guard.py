from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import BaseModel

from astp.models import Engagement, OperationalStatus, ProgramOperationalAttestation


class OperationalGuardResult(BaseModel):
    allowed: bool
    reason: str
    age_seconds: float | None = None


def evaluate_operational_guard(
    engagement: Engagement,
    attestation: ProgramOperationalAttestation | None,
    *,
    now: datetime | None = None,
) -> OperationalGuardResult:
    if engagement.program is None or not engagement.program.requires_online:
        return OperationalGuardResult(allowed=True, reason="online attestation not required")
    if attestation is None:
        return OperationalGuardResult(allowed=False, reason="online attestation required")
    current = now or datetime.now(UTC)
    age = max(0.0, (current - attestation.observed_at).total_seconds())
    if attestation.status != OperationalStatus.ONLINE:
        return OperationalGuardResult(
            allowed=False,
            reason=f"program operational status is {attestation.status.value}",
            age_seconds=age,
        )
    max_age = engagement.program.operational_attestation_max_age_seconds
    if current > attestation.observed_at + timedelta(seconds=max_age):
        return OperationalGuardResult(
            allowed=False,
            reason="program operational attestation is stale",
            age_seconds=age,
        )
    if attestation.source_content_sha256 != engagement.program.source_content_sha256:
        return OperationalGuardResult(
            allowed=False,
            reason="program operational attestation revision mismatch",
            age_seconds=age,
        )
    return OperationalGuardResult(
        allowed=True, reason="program is freshly attested online", age_seconds=age
    )
