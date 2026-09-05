from __future__ import annotations

from datetime import UTC, datetime
from urllib.request import Request

import pytest

from astp.approval_workflow import ApprovalDecision, record_high_risk_approval
from astp.assessment_completion import evaluate_pentest_completion
from astp.assessment_coverage import current_assessment_coverage
from astp.assessment_run_state import (
    load_assessment_run_state,
    new_assessment_run_state,
    save_assessment_run_state,
)
from astp.auth_session import (
    AuthBinding,
    AuthInjection,
    assert_session_target_allowed,
    build_auth_session_profile,
)
from astp.authenticated_transport import AuthenticatedObservationTransport
from astp.authorization_differential import build_authorization_differential_plan
from astp.browser_worker_contract import BrowserWorkerContract
from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.end_to_end_plan import build_end_to_end_assessment_plan
from astp.external_adapter_contracts import builtin_external_adapter_contracts
from astp.pentest_readiness import current_pentest_readiness
from astp.retest_scheduler import build_retest_request
from astp.secret_broker import SecretKind, build_secret_reference
from astp.secret_runtime import ResolvedSecret, resolve_secret_reference
from astp.transport import ResolvedEndpoint, TransportResponse
from astp.verification_broker import VerificationAuthorizationCandidate
from astp.verification_execution import prepare_verification_execution


def _secret():
    return build_secret_reference(
        SecretKind.API_TOKEN,
        "env",
        "ASTP_TEST_TOKEN",
        allowed_origins=["https://example.com"],
        allowed_identity="alice",
    )


def _session():
    binding = AuthBinding(secret=_secret(), injection=AuthInjection.BEARER)
    return build_auth_session_profile("alice", [binding], ["https://example.com"])


def test_m127_auth_session_is_origin_and_identity_bound():
    session = _session()
    assert_session_target_allowed(session, "https://example.com/private")
    with pytest.raises(ValueError):
        assert_session_target_allowed(session, "https://other.example/private")


def test_m128_secret_runtime_resolves_reference_without_repr_leak():
    resolved = resolve_secret_reference(_secret(), environment={"ASTP_TEST_TOKEN": "top-secret"})
    assert resolved.value == "top-secret"
    assert "top-secret" not in repr(resolved)


def test_m129_authenticated_transport_injects_only_at_boundary():
    captured = {}

    class FakeTransport:
        def open(self, request, *, timeout):
            captured.update(dict(request.header_items()))
            return TransportResponse(
                response=object(),
                resolved_endpoint=ResolvedEndpoint(
                    hostname="example.com", port=443, addresses=("203.0.113.10",)
                ),
            )

    transport = AuthenticatedObservationTransport(
        FakeTransport(),
        _session(),
        lambda reference: ResolvedSecret(reference.id, "top-secret"),
    )
    transport.open(Request("https://example.com/private"), timeout=1.0)
    assert captured["Authorization"] == "Bearer top-secret"


def test_m130_differential_plan_requires_two_distinct_identities():
    plan = build_authorization_differential_plan("https://example.com/object/1", "alice", "bob")
    assert plan.fresh_permit_per_request is True
    with pytest.raises(ValueError):
        build_authorization_differential_plan("https://example.com/object/1", "alice", "alice")


def test_m131_browser_contract_is_observation_only_and_not_runtime_ready():
    contract = BrowserWorkerContract()
    assert contract.permit_required is True
    assert contract.form_submission_allowed is False
    assert contract.runtime_ready is False


def test_m132_external_adapter_contracts_are_bounded_and_not_executable_yet():
    adapters = builtin_external_adapter_contracts()
    assert len(adapters) == 3
    assert all(item.permit_required for item in adapters)
    assert all(not item.arbitrary_arguments_allowed for item in adapters)
    assert all(not item.runtime_ready for item in adapters)


def test_m133_verification_execution_remains_policy_and_permit_gated():
    candidate = VerificationAuthorizationCandidate(
        queue_item_id="queue-1",
        finding_id="finding-1",
        finding_key="cors",
        review_hash="a" * 64,
    )
    action = CapabilityAction(
        capability_id="http.observation.v1",
        operation=CapabilityOperation.HTTP_GET,
        target="https://example.com/",
    )
    envelope = prepare_verification_execution(candidate, action)
    assert envelope.requires_policy_authorization is True
    assert envelope.requires_fresh_permit is True
    assert envelope.execution_performed is False


def test_m134_high_risk_approval_never_enables_autonomous_execution():
    approval = record_high_risk_approval(
        "action-1", "operator", ApprovalDecision.APPROVE, now=datetime(2026, 9, 5, tzinfo=UTC)
    )
    assert approval.autonomous_execution_allowed is False
    assert approval.exact_action_binding is True


def test_m135_assessment_state_is_durable(tmp_path):
    path = tmp_path / "runs.db"
    state = new_assessment_run_state("run-1", "eng-1", "digest-1")
    save_assessment_run_state(path, state)
    loaded = load_assessment_run_state(path, "run-1")
    assert loaded == state


def test_m136_retest_request_requires_current_guards():
    request = build_retest_request("finding-1", now=datetime(2026, 9, 5, tzinfo=UTC))
    assert request.requires_current_policy is True
    assert request.requires_fresh_operational_attestation is True
    assert request.requires_fresh_permit is True


def test_m137_coverage_marks_authenticated_http_available():
    coverage = current_assessment_coverage()
    assert coverage.authenticated_http is True
    assert coverage.browser_dynamic is False
    assert coverage.completed_dimensions < coverage.total_dimensions


def test_m138_end_to_end_plan_exposes_remaining_capability_gaps():
    plan = build_end_to_end_assessment_plan(
        "eng-1", "https://example.com/", auth_session=_session()
    )
    assert plan.safe_surface_action_count >= 3
    assert plan.auth_session_id is not None
    assert "isolated browser worker" in plan.unresolved_capabilities
    assert plan.execution_enabled is False


def test_m139_readiness_closes_authenticated_session_blocker_only():
    readiness = current_pentest_readiness()
    assert readiness.authenticated_session_execution is True
    assert readiness.browser_execution_worker is False
    assert readiness.full_pentest_ready is False


def test_m140_completion_is_explicitly_not_full_pentest_ready():
    completion = evaluate_pentest_completion()
    assert completion.safe_observation_end_to_end is True
    assert completion.authenticated_observation_end_to_end is True
    assert completion.complete_end_to_end is False


def test_m141_secret_binding_rejects_origin_expansion():
    binding = AuthBinding(secret=_secret(), injection=AuthInjection.BEARER)
    with pytest.raises(ValueError):
        build_auth_session_profile("alice", [binding], ["https://other.example"])


def test_m142_custom_header_requires_name():
    binding = AuthBinding(secret=_secret(), injection=AuthInjection.HEADER)
    with pytest.raises(ValueError):
        build_auth_session_profile("alice", [binding], ["https://example.com"])


def test_m143_session_does_not_export_raw_secrets():
    payload = _session().model_dump_json()
    assert "top-secret" not in payload
    assert '"raw_secrets_exportable":false' in payload


def test_m144_http_action_remains_exactly_identified():
    action = CapabilityAction(
        capability_id="http.observation.v1",
        operation=CapabilityOperation.HTTP_GET,
        target="https://example.com/private",
        identity="alice",
    )
    assert len(action.action_id()) == 64
