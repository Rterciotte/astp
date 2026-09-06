from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel

from astp.authorization import AuthorizationRequest, authorize_test
from astp.models import Decision, Engagement, ProgramOperationalAttestation, TestDefinition
from astp.operational_lease import ProgramOperationalLease
from astp.permits import SignedExecutionPermit, issue_execution_permit
from astp.work_queue import WorkQueueItem


class PermitBrokerReceipt(BaseModel):
    schema_version: str = "1"
    queue_id: str
    engagement_id: str
    test_id: str
    target: str
    permit: SignedExecutionPermit
    issued_at: datetime


def broker_queue_item_permit(
    item: WorkQueueItem,
    engagement: Engagement,
    test: TestDefinition,
    signing_key: str | bytes,
    *,
    key_id: str = "local-v1",
    ttl_seconds: int = 120,
    operational_attestation: ProgramOperationalAttestation | None = None,
    operational_lease: ProgramOperationalLease | None = None,
    semantic_exclusion_clears: set[str] | None = None,
    requested_rps: float | None = None,
    now: datetime | None = None,
) -> PermitBrokerReceipt:
    """Re-authorize one queue item and issue one exact-action permit; never execute it."""
    if item.engagement_id != engagement.id:
        raise ValueError("queue item belongs to a different engagement")
    if item.test_id != test.id:
        raise ValueError("queue item belongs to a different test")
    if not item.requires_new_permit:
        raise ValueError("queue item does not require a new permit")

    current = now or datetime.now(UTC)
    request = AuthorizationRequest(
        target=item.target,
        http_method=item.method,
        requested_requests_per_second=requested_rps,
        program_operational_attestation=operational_attestation,
        program_operational_lease=operational_lease,
        semantic_exclusion_clears=set(semantic_exclusion_clears or set()),
        semantic_exclusion_matches=set(),
        now=current,
    )
    authorization = authorize_test(engagement, test, request)
    if authorization.decision != Decision.ALLOW:
        details = "; ".join(
            check.message
            for check in authorization.checks
            if check.status.value in {"review", "fail"}
        )
        raise ValueError(
            "permit broker re-authorization did not return ALLOW: "
            f"{authorization.decision.value}" + (f" ({details})" if details else "")
        )
    permit = issue_execution_permit(
        engagement,
        test,
        request,
        signing_key,
        ttl_seconds=ttl_seconds,
        key_id=key_id,
        now=current,
    )
    if permit.payload.target != item.target or permit.payload.http_method != item.method.upper():
        raise ValueError("issued permit is not bound to the exact queue action")
    return PermitBrokerReceipt(
        queue_id=item.queue_id,
        engagement_id=engagement.id,
        test_id=test.id,
        target=item.target,
        permit=permit,
        issued_at=current,
    )
