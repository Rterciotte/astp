from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from astp.models import OperationalStatus, ProgramOperationalAttestation
from astp.program_models import BugBountyProgram


def create_operational_attestation(
    program: BugBountyProgram,
    *,
    status: OperationalStatus,
    source_type: str,
    observed_at: datetime | None = None,
    note: str | None = None,
) -> ProgramOperationalAttestation:
    source_type = source_type.strip()
    if not source_type:
        raise ValueError("source_type cannot be empty")
    current = observed_at or datetime.now(UTC)
    payload = (
        f"{program.id}|{program.source.content_sha256}|{status.value}|"
        f"{current.isoformat()}|{source_type}"
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return ProgramOperationalAttestation(
        id=f"opatt-{digest}",
        program_id=program.id,
        source_content_sha256=program.source.content_sha256,
        status=status,
        observed_at=current,
        source_type=source_type,
        source_url=program.source.source_url,
        note=note,
    )
