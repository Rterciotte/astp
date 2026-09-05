from datetime import UTC, datetime, timedelta

from astp.models import (
    Constraints,
    Engagement,
    MethodPolicy,
    OperationalStatus,
    ProgramBinding,
    ProgramOperationalAttestation,
    ScopePolicy,
)
from astp.operational_guard import evaluate_operational_guard


def test_guard_rejects_stale_attestation():
    now = datetime.now(UTC)
    program = ProgramBinding(
        program_id="p",
        platform="x",
        source_content_sha256="a" * 64,
        requires_online=True,
        operational_attestation_max_age_seconds=60,
    )
    engagement = Engagement(
        id="e",
        name="e",
        scope=ScopePolicy(),
        methods=MethodPolicy(),
        constraints=Constraints(),
        program=program,
    )
    attestation = ProgramOperationalAttestation(
        id="a",
        program_id="p",
        source_content_sha256="a" * 64,
        status=OperationalStatus.ONLINE,
        source_type="operator",
        observed_at=now - timedelta(seconds=61),
    )
    assert evaluate_operational_guard(engagement, attestation, now=now).allowed is False
