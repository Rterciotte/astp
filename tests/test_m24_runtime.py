from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from astp.action import http_target_rate_key
from astp.lifecycle import PermitLifecycleStatus
from astp.models import (
    Constraints,
    Decision,
    Engagement,
    MethodPolicy,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as SecurityTestDefinition,
)
from astp.permits import PermitVerificationRequest, issue_execution_permit
from astp.runtime_state import (
    admit_worker_action,
    revoke_runtime_permit,
    runtime_permit_status,
)

KEY = "0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def _engagement() -> Engagement:
    return Engagement(
        id="runtime-test",
        name="Runtime Test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.com")],
        ),
        methods=MethodPolicy(
            passive=Decision.ALLOW,
            safe_active=Decision.ALLOW,
            state_changing=Decision.APPROVAL_REQUIRED,
            intrusive=Decision.DENY,
        ),
        constraints=Constraints(max_requests_per_second=1),
    )


def _test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="observation.http",
        title="HTTP observation",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
    )


def _permit(target: str, *, now: datetime = NOW):
    engagement = _engagement()
    test = _test()
    request = PermitVerificationRequest(
        target=target,
        http_method="GET",
        identity=None,
        requested_requests_per_second=1,
        now=now,
    )
    from astp.authorization import AuthorizationRequest

    permit = issue_execution_permit(
        engagement,
        test,
        AuthorizationRequest(
            target=target,
            http_method="GET",
            requested_requests_per_second=1,
            now=now,
        ),
        KEY,
        now=now,
    )
    return engagement, test, permit, request


def test_runtime_admission_consumes_permit_atomically(tmp_path: Path) -> None:
    target = "https://example.com/health"
    engagement, test, permit, request = _permit(target)
    db = tmp_path / "runtime.db"

    result = admit_worker_action(
        permit,
        engagement,
        test,
        request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )

    assert result.accepted is True
    assert runtime_permit_status(db, permit.payload.permit_id) == PermitLifecycleStatus.CONSUMED


def test_rate_rejection_does_not_consume_second_permit(tmp_path: Path) -> None:
    target = "https://example.com/health"
    db = tmp_path / "runtime.db"
    engagement, test, first, first_request = _permit(target)
    _, _, second, second_request = _permit(target)

    admitted = admit_worker_action(
        first,
        engagement,
        test,
        first_request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )
    rejected = admit_worker_action(
        second,
        engagement,
        test,
        second_request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )

    assert admitted.accepted is True
    assert rejected.accepted is False
    assert rejected.retry_after_seconds > 0
    assert runtime_permit_status(db, second.payload.permit_id) == PermitLifecycleStatus.AVAILABLE


def test_rate_rejected_permit_can_be_used_after_window(tmp_path: Path) -> None:
    target = "https://example.com/health"
    db = tmp_path / "runtime.db"
    engagement, test, first, first_request = _permit(target)
    _, _, second, second_request = _permit(target)

    admit_worker_action(
        first,
        engagement,
        test,
        first_request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )
    rejected = admit_worker_action(
        second,
        engagement,
        test,
        second_request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )
    assert rejected.accepted is False

    later_request = second_request.model_copy(update={"now": NOW + timedelta(seconds=2)})
    admitted = admit_worker_action(
        second,
        engagement,
        test,
        later_request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )
    assert admitted.accepted is True


def test_runtime_revocation_blocks_admission(tmp_path: Path) -> None:
    target = "https://example.com/health"
    db = tmp_path / "runtime.db"
    engagement, test, permit, request = _permit(target)

    status = revoke_runtime_permit(db, permit.payload.permit_id, reason="scope changed", now=NOW)
    result = admit_worker_action(
        permit,
        engagement,
        test,
        request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )

    assert status == PermitLifecycleStatus.REVOKED
    assert result.accepted is False
    assert result.lifecycle_status == PermitLifecycleStatus.REVOKED


def test_consumed_runtime_permit_cannot_be_revoked(tmp_path: Path) -> None:
    target = "https://example.com/health"
    db = tmp_path / "runtime.db"
    engagement, test, permit, request = _permit(target)
    admit_worker_action(
        permit,
        engagement,
        test,
        request,
        KEY,
        db,
        action_key=http_target_rate_key(target),
        max_requests_per_second=1,
    )

    with pytest.raises(ValueError, match="consumed permit"):
        revoke_runtime_permit(db, permit.payload.permit_id, reason="too late", now=NOW)


def test_worker_capability_rejects_unsupported_method() -> None:
    from astp.contracts import HTTP_OBSERVATION_CAPABILITY, ensure_capability_compatible

    target = "https://example.com/health"
    _, _, permit, _ = _permit(target)
    with pytest.raises(ValueError, match="does not support HTTP method"):
        ensure_capability_compatible(
            HTTP_OBSERVATION_CAPABILITY,
            permit,
            target=target,
            method="POST",
            timeout_seconds=10,
            max_body_bytes=1024,
        )


def test_same_runtime_permit_is_admitted_once_under_concurrency(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    target = "https://example.com/health"
    db = tmp_path / "runtime.db"
    engagement, test, permit, request = _permit(target)

    def attempt():
        return admit_worker_action(
            permit,
            engagement,
            test,
            request,
            KEY,
            db,
            action_key=http_target_rate_key(target),
            max_requests_per_second=10,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))

    assert sum(result.accepted for result in results) == 1
    assert runtime_permit_status(db, permit.payload.permit_id) == PermitLifecycleStatus.CONSUMED
