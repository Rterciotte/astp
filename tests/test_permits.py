from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from astp.authorization import AuthorizationRequest, authorize_test
from astp.models import (
    Constraints,
    Decision,
    Engagement,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as SecurityTestDefinition,
)
from astp.permits import (
    MAX_PERMIT_TTL_SECONDS,
    PermitVerificationRequest,
    SignedExecutionPermit,
    issue_execution_permit,
    verify_execution_permit,
)

KEY = "k" * 32
NOW = datetime(2026, 8, 28, 21, 0, tzinfo=UTC)


def engagement() -> Engagement:
    return Engagement(
        id="e1",
        name="Permit test",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]),
        constraints=Constraints(max_requests_per_second=2),
    )


def make_test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="authorization.object_access",
        title="Object access",
        category="authorization",
        risk_class="safe_active",
        required_context=["authenticated_identity"],
    )


def authorized_request() -> AuthorizationRequest:
    return AuthorizationRequest(
        target="https://api.example.com/v1/users/123",
        available_context={"authenticated_identity"},
        http_method="GET",
        identity="researcher",
        requested_requests_per_second=1,
        now=NOW,
    )


def permit() -> SignedExecutionPermit:
    current_engagement = engagement()
    current_test = make_test()
    request = authorized_request()
    result = authorize_test(current_engagement, current_test, request)
    assert result.decision == Decision.ALLOW
    return issue_execution_permit(
        current_engagement,
        current_test,
        request,
        KEY,
        now=NOW,
    )


def verification_request(**changes: object) -> PermitVerificationRequest:
    values: dict[str, object] = {
        "target": "https://api.example.com/v1/users/123",
        "http_method": "GET",
        "identity": "researcher",
        "requested_requests_per_second": 1,
        "now": NOW + timedelta(seconds=10),
    }
    values.update(changes)
    return PermitVerificationRequest(**values)


def test_valid_permit_verifies() -> None:
    result = verify_execution_permit(
        permit(),
        engagement(),
        make_test(),
        verification_request(),
        KEY,
    )
    assert result.valid is True
    assert all(check.status.value == "pass" for check in result.checks)


def test_permit_cannot_be_issued_after_denial() -> None:
    current_engagement = engagement()
    current_test = make_test()
    request = authorized_request().model_copy(update={"target": "https://outside.example.net"})
    result = authorize_test(current_engagement, current_test, request)
    assert result.decision == Decision.DENY
    with pytest.raises(ValueError, match="ALLOW"):
        issue_execution_permit(
            current_engagement,
            current_test,
            request,
            KEY,
            now=NOW,
        )


def test_tampered_payload_fails_signature_verification() -> None:
    signed = permit()
    payload = signed.model_dump(mode="json")
    payload["payload"]["target"] = "https://api.example.com/v1/admin"
    tampered = SignedExecutionPermit.model_validate(payload)
    result = verify_execution_permit(
        tampered,
        engagement(),
        make_test(),
        verification_request(target="https://api.example.com/v1/admin"),
        KEY,
    )
    assert result.valid is False
    assert result.checks[-1].name == "signature"


def test_wrong_key_fails_signature_verification() -> None:
    result = verify_execution_permit(
        permit(),
        engagement(),
        make_test(),
        verification_request(),
        "x" * 32,
    )
    assert result.valid is False
    assert result.checks[-1].name == "signature"


def test_expired_permit_is_rejected() -> None:
    result = verify_execution_permit(
        permit(),
        engagement(),
        make_test(),
        verification_request(now=NOW + timedelta(minutes=6)),
        KEY,
    )
    assert result.valid is False
    assert result.checks[-1].name == "time_window"


def test_action_binding_rejects_different_target() -> None:
    result = verify_execution_permit(
        permit(),
        engagement(),
        make_test(),
        verification_request(target="https://api.example.com/v1/users/999"),
        KEY,
    )
    assert result.valid is False
    assert result.checks[-1].name == "action_binding"


def test_policy_change_invalidates_existing_permit() -> None:
    changed = deepcopy(engagement())
    changed.constraints.max_requests_per_second = 1
    result = verify_execution_permit(
        permit(),
        changed,
        make_test(),
        verification_request(),
        KEY,
    )
    assert result.valid is False
    assert result.checks[-1].name == "policy_digest"


def test_permit_rate_limit_is_enforced() -> None:
    result = verify_execution_permit(
        permit(),
        engagement(),
        make_test(),
        verification_request(requested_requests_per_second=3),
        KEY,
    )
    assert result.valid is False
    assert result.checks[-1].name == "rate_limit"


def test_ttl_is_bounded() -> None:
    current_engagement = engagement()
    current_test = make_test()
    request = authorized_request()
    with pytest.raises(ValueError, match="TTL"):
        issue_execution_permit(
            current_engagement,
            current_test,
            request,
            KEY,
            ttl_seconds=MAX_PERMIT_TTL_SECONDS + 1,
            now=NOW,
        )


def test_short_signing_key_is_rejected() -> None:
    current_engagement = engagement()
    current_test = make_test()
    request = authorized_request()
    with pytest.raises(ValueError, match="32 bytes"):
        issue_execution_permit(
            current_engagement,
            current_test,
            request,
            "too-short",
            now=NOW,
        )
