from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel

from astp.findings import CorrelatedFinding


class FindingStatus(str, Enum):
    OPEN = "open"
    REMEDIATION_PENDING = "remediation_pending"
    RETEST_REQUIRED = "retest_required"
    RESOLVED = "resolved"


class FindingLifecycle(BaseModel):
    finding_id: str
    status: FindingStatus
    updated_at: datetime


def request_retest(finding: CorrelatedFinding, *, now: datetime | None = None) -> FindingLifecycle:
    return FindingLifecycle(
        finding_id=finding.id,
        status=FindingStatus.RETEST_REQUIRED,
        updated_at=now or datetime.now(UTC),
    )


def complete_retest(
    lifecycle: FindingLifecycle, *, still_present: bool, now: datetime | None = None
) -> FindingLifecycle:
    if lifecycle.status != FindingStatus.RETEST_REQUIRED:
        raise ValueError("finding is not awaiting retest")
    return lifecycle.model_copy(
        update={
            "status": FindingStatus.OPEN if still_present else FindingStatus.RESOLVED,
            "updated_at": now or datetime.now(UTC),
        }
    )
