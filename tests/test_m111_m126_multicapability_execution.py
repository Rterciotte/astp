from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from astp.assessment_execution import build_assessment_execution_plan
from astp.authorization import AuthorizationRequest
from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.capability_grant import issue_capability_grant, verify_capability_grant
from astp.capability_observation import observe_dns, observe_tls
from astp.execution_intent import build_execution_intent
from astp.models import (
    Constraints,
    Engagement,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as SecurityTestDefinition,
)
from astp.permits import issue_execution_permit
from astp.safe_assessment_profile import SafeAssessmentProfile

KEY = "k" * 32
NOW = datetime(2026, 9, 5, 3, 0, tzinfo=UTC)


def engagement() -> Engagement:
    return Engagement(
        id="e1",
        name="Capability test",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.com")]),
        constraints=Constraints(max_requests_per_second=2),
    )


def security_test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="observation.network",
        title="Network observation",
        category="observation",
        risk_class="safe_active",
    )


def permit(target: str = "example.com"):
    req = AuthorizationRequest(target=target, requested_requests_per_second=1, now=NOW)
    return issue_execution_permit(engagement(), security_test(), req, KEY, now=NOW)


def test_capability_action_id_is_deterministic() -> None:
    a = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    assert a.action_id() == a.model_copy().action_id()


def test_grant_binds_exact_action() -> None:
    action = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    signed = permit()
    grant = issue_capability_grant(signed, action, engagement(), security_test(), KEY, now=NOW)
    valid, _ = verify_capability_grant(
        grant,
        signed,
        action,
        KEY,
        now=NOW + timedelta(seconds=1),
    )
    assert valid is True


def test_grant_rejects_changed_operation() -> None:
    original = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    changed = original.model_copy(update={"operation": CapabilityOperation.DNS_AAAA})
    signed = permit()
    grant = issue_capability_grant(signed, original, engagement(), security_test(), KEY, now=NOW)
    valid, message = verify_capability_grant(
        grant,
        signed,
        changed,
        KEY,
        now=NOW + timedelta(seconds=1),
    )
    assert valid is False
    assert "action_id" in message


def test_grant_rejects_tampered_underlying_permit() -> None:
    action = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    signed = permit()
    payload = signed.model_dump(mode="python")
    payload["payload"]["target"] = "outside.example"
    tampered = signed.__class__.model_validate(payload)
    with pytest.raises(ValueError, match="failed verification"):
        issue_capability_grant(tampered, action, engagement(), security_test(), KEY, now=NOW)


def test_dns_observation_uses_injected_resolver_and_registers_evidence(tmp_path: Path) -> None:
    action = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    signed = permit()
    grant = issue_capability_grant(signed, action, engagement(), security_test(), KEY, now=NOW)

    def resolver(*_args):
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    evidence = observe_dns(
        grant,
        signed,
        action,
        engagement(),
        security_test(),
        KEY,
        state_path=tmp_path / "state.json",
        evidence_path=tmp_path / "dns.json",
        manifest_path=tmp_path / "manifest.jsonl",
        resolver=resolver,
        now=NOW + timedelta(seconds=1),
    )
    assert evidence.addresses == ["93.184.216.34"]
    assert (tmp_path / "dns.json").exists()
    assert (tmp_path / "manifest.jsonl").exists()


def test_tls_observation_uses_injected_connector(tmp_path: Path) -> None:
    action = CapabilityAction(
        capability_id="tls.handshake.v1",
        operation=CapabilityOperation.TLS_HANDSHAKE,
        target="example.com",
        port=443,
    )
    signed = permit()
    grant = issue_capability_grant(signed, action, engagement(), security_test(), KEY, now=NOW)

    def connector(host: str, port: int, timeout: float):
        assert host == "example.com"
        assert port == 443
        assert timeout > 0
        return "TLSv1.3", "TLS_AES_256_GCM_SHA384", "a" * 64

    evidence = observe_tls(
        grant,
        signed,
        action,
        engagement(),
        security_test(),
        KEY,
        state_path=tmp_path / "state.json",
        evidence_path=tmp_path / "tls.json",
        manifest_path=tmp_path / "manifest.jsonl",
        connector=connector,
        now=NOW + timedelta(seconds=1),
    )
    assert evidence.protocol == "TLSv1.3"
    assert evidence.peer_certificate_sha256 == "a" * 64


def test_non_http_grant_rejects_http_bound_permit() -> None:
    req = AuthorizationRequest(
        target="example.com",
        http_method="GET",
        requested_requests_per_second=1,
        now=NOW,
    )
    signed = issue_execution_permit(engagement(), security_test(), req, KEY, now=NOW)
    action = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    with pytest.raises(ValueError, match="failed verification|without http_method"):
        issue_capability_grant(signed, action, engagement(), security_test(), KEY, now=NOW)


def test_safe_assessment_profile_excludes_intrusive_automation() -> None:
    profile = SafeAssessmentProfile()
    assert profile.state_changing_allowed is False
    assert profile.credential_attacks_allowed is False
    assert profile.exploit_payloads_allowed is False
    assert profile.fresh_permit_per_action is True


def test_execution_plan_defaults_to_disabled() -> None:
    action = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    intent = build_execution_intent("e1", action)
    plan = build_assessment_execution_plan("e1", [intent])
    assert plan.execution_enabled is False
    assert plan.max_network_actions == 20
    assert plan.intents[0].requires_fresh_permit is True


def test_permit_replay_is_rejected_before_second_dns_action(tmp_path: Path) -> None:
    action = CapabilityAction(
        capability_id="dns.lookup.v1",
        operation=CapabilityOperation.DNS_A,
        target="example.com",
    )
    signed = permit()
    grant = issue_capability_grant(signed, action, engagement(), security_test(), KEY, now=NOW)

    calls = {"count": 0}

    def resolver(*_args):
        calls["count"] += 1
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    kwargs = {
        "evidence_path": tmp_path / "dns.json",
        "manifest_path": tmp_path / "manifest.jsonl",
        "resolver": resolver,
        "now": NOW + timedelta(seconds=1),
    }
    observe_dns(
        grant,
        signed,
        action,
        engagement(),
        security_test(),
        KEY,
        state_path=tmp_path / "state.json",
        **kwargs,
    )
    with pytest.raises(RuntimeError, match="replay rejected"):
        observe_dns(
            grant,
            signed,
            action,
            engagement(),
            security_test(),
            KEY,
            state_path=tmp_path / "state.json",
            **kwargs,
        )
    assert calls["count"] == 1


def test_safe_surface_plan_is_planning_only() -> None:
    from astp.assessment_cycle import plan_safe_surface_observations

    plan = plan_safe_surface_observations("https://example.com/")
    assert plan.network_execution_performed is False
    assert {item.capability_id for item in plan.actions} == {
        "dns.lookup.v1",
        "tls.handshake.v1",
        "http.observation.v1",
    }


def test_pentest_readiness_remains_false_until_active_layers_exist() -> None:
    from astp.pentest_readiness import current_pentest_readiness

    readiness = current_pentest_readiness()
    assert readiness.full_pentest_ready is False
    assert readiness.vulnerability_specific_active_verification is False
    assert readiness.blockers
