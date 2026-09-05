from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from astp.models import Engagement, TestDefinition
from astp.permits import policy_digest


class PolicySnapshot(BaseModel):
    schema_version: str = "1"
    engagement_id: str
    test_id: str
    digest: str
    captured_at: datetime


def capture_policy_snapshot(
    engagement: Engagement,
    test: TestDefinition,
    *,
    now: datetime | None = None,
) -> PolicySnapshot:
    return PolicySnapshot(
        engagement_id=engagement.id,
        test_id=test.id,
        digest=policy_digest(engagement, test),
        captured_at=now or datetime.now(UTC),
    )


def assert_policy_unchanged(
    snapshot: PolicySnapshot,
    engagement: Engagement,
    test: TestDefinition,
) -> None:
    if snapshot.engagement_id != engagement.id or snapshot.test_id != test.id:
        raise ValueError("policy snapshot is bound to a different engagement or test")
    if snapshot.digest != policy_digest(engagement, test):
        raise ValueError("policy drift detected; session must stop and be re-planned")
