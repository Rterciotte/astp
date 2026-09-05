from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict


class RetestRequest(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    finding_id: str
    requested_at: datetime
    requires_current_policy: bool = True
    requires_fresh_operational_attestation: bool = True
    requires_fresh_permit: bool = True
    execution_performed: bool = False


def build_retest_request(finding_id: str, *, now: datetime | None = None) -> RetestRequest:
    timestamp = now or datetime.now(UTC)
    digest = hashlib.sha256(f"{finding_id}|{timestamp.isoformat()}".encode()).hexdigest()[:16]
    return RetestRequest(id=f"retest-{digest}", finding_id=finding_id, requested_at=timestamp)
