from datetime import datetime, timedelta, timezone
from pathlib import Path

from astp.authorization import AuthorizationRequest
from astp.lifecycle import (
    PermitLifecycleStatus,
    append_audit_event,
    consume_execution_permit,
    permit_status,
    revoke_permit,
    verify_audit_chain,
)
from astp.models import (
    Constraints,
    Engagement,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
    TestDefinition as SecurityTestDefinition,
)
from astp.permits import PermitVerificationRequest, issue_execution_permit, verify_execution_permit

KEY_V1 = "a" * 32
KEY_V2 = "b" * 32
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)


def engagement() -> Engagement:
    return Engagement(
        id="e1",
        name="Lifecycle test",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]),
        constraints=Constraints(max_requests_per_second=2),
    )


def security_test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="authorization.object_access",
        title="Object access",
        category="authorization",
        risk_class="safe_active",
        required_context=["authenticated_identity"],
    )


def authorization_request() -> AuthorizationRequest:
    return AuthorizationRequest(
        target="https://api.example.com/v1/users/123",
        available_context={"authenticated_identity"},
        http_method="GET",
        identity="researcher",
        requested_requests_per_second=1,
        now=NOW,
    )


def verification_request() -> PermitVerificationRequest:
    return PermitVerificationRequest(
        target="https://api.example.com/v1/users/123",
        http_method="GET",
        identity="researcher",
        requested_requests_per_second=1,
        now=NOW + timedelta(seconds=5),
    )


def signed_permit(key_id: str = "v1", key: str = KEY_V1):
    return issue_execution_permit(
        engagement(),
        security_test(),
        authorization_request(),
        key,
        key_id=key_id,
        now=NOW,
    )


def test_permit_is_consumed_exactly_once(tmp_path: Path) -> None:
    state_path = tmp_path / "permit-state.json"
    permit = signed_permit()
    first = consume_execution_permit(
        permit,
        engagement(),
        security_test(),
        verification_request(),
        {"v1": KEY_V1},
        state_path,
    )
    second = consume_execution_permit(
        permit,
        engagement(),
        security_test(),
        verification_request(),
        {"v1": KEY_V1},
        state_path,
    )
    assert first.accepted is True
    assert second.accepted is False
    assert second.lifecycle_status == PermitLifecycleStatus.CONSUMED


def test_revoked_permit_cannot_be_consumed(tmp_path: Path) -> None:
    state_path = tmp_path / "permit-state.json"
    permit = signed_permit()
    revoke_permit(state_path, permit.payload.permit_id, reason="operator revoked", now=NOW)
    result = consume_execution_permit(
        permit,
        engagement(),
        security_test(),
        verification_request(),
        {"v1": KEY_V1},
        state_path,
    )
    assert result.accepted is False
    assert result.lifecycle_status == PermitLifecycleStatus.REVOKED


def test_invalid_permit_is_not_consumed(tmp_path: Path) -> None:
    state_path = tmp_path / "permit-state.json"
    permit = signed_permit()
    result = consume_execution_permit(
        permit,
        engagement(),
        security_test(),
        verification_request(),
        {"v1": KEY_V2},
        state_path,
    )
    assert result.accepted is False
    assert permit_status(state_path, permit.payload.permit_id) == PermitLifecycleStatus.AVAILABLE


def test_keyring_can_verify_retired_key() -> None:
    permit = signed_permit(key_id="v1", key=KEY_V1)
    result = verify_execution_permit(
        permit,
        engagement(),
        security_test(),
        verification_request(),
        {"v1": KEY_V1, "v2": KEY_V2},
    )
    assert result.valid is True


def test_unknown_key_id_is_rejected() -> None:
    permit = signed_permit(key_id="v1", key=KEY_V1)
    result = verify_execution_permit(
        permit,
        engagement(),
        security_test(),
        verification_request(),
        {"v2": KEY_V2},
    )
    assert result.valid is False
    assert result.checks[-1].name == "key_id"


def test_audit_chain_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    append_audit_event(path, "permit.issued", permit_id="p1", now=NOW)
    append_audit_event(path, "permit.consumed", permit_id="p1", now=NOW + timedelta(seconds=1))
    valid, message = verify_audit_chain(path)
    assert valid is True
    assert "2 records" in message


def test_audit_chain_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    append_audit_event(path, "permit.issued", permit_id="p1", now=NOW)
    append_audit_event(path, "permit.consumed", permit_id="p1", now=NOW + timedelta(seconds=1))
    text = path.read_text(encoding="utf-8").replace("permit.issued", "permit.revoked", 1)
    path.write_text(text, encoding="utf-8")
    valid, _ = verify_audit_chain(path)
    assert valid is False


def test_revoke_records_status_atomically(tmp_path: Path) -> None:
    state_path = tmp_path / "nested" / "permit-state.json"
    entry = revoke_permit(state_path, "p1", reason="scope changed", now=NOW)
    assert entry.status == PermitLifecycleStatus.REVOKED
    assert permit_status(state_path, "p1") == PermitLifecycleStatus.REVOKED


def test_consumed_permit_cannot_be_retroactively_revoked(tmp_path: Path) -> None:
    state_path = tmp_path / "permit-state.json"
    permit = signed_permit()
    consume_execution_permit(
        permit,
        engagement(),
        security_test(),
        verification_request(),
        {"v1": KEY_V1},
        state_path,
    )
    try:
        revoke_permit(state_path, permit.payload.permit_id, reason="too late", now=NOW)
    except ValueError as exc:
        assert "consumed" in str(exc)
    else:
        raise AssertionError("expected consumed permit revocation to fail")
