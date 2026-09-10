from datetime import UTC, datetime

import pytest

from astp.auth_workflow import AuthWorkflowKind, AuthWorkflowPlan
from astp.bounded_discovery import deterministic_wordlist, discover_bounded
from astp.detector_policy import (
    DetectorDecisionCode,
    DetectorPolicyContext,
    MentionDisposition,
    decide_detector,
)
from astp.detector_registry import RuntimeState, builtin_detector_registry
from astp.differential_access import IdentityObservation, compare_identity_observations
from astp.m52_tool_contracts import (
    BoundedToolJob,
    ToolEngine,
    compile_tool_argv,
    reject_arbitrary_arguments,
)
from astp.nuclei_templates import NucleiTemplateMetadata, TemplateRisk, classify_nuclei_template
from astp.oast import LocalFakeOastProvider, OastCallback, correlate_oast
from astp.proof_model import ProofStateV2
from astp.secret_exposure import SecretKind, analyze_exposed_content


def _cap(detector_id):
    return next(item for item in builtin_detector_registry() if item.detector_id == detector_id)


def _context(**changes):
    values = {"target_in_scope": True, "remaining_requests": 100}
    values.update(changes)
    return DetectorPolicyContext(**values)


def test_not_mentioned_is_not_denied_for_ready_detector():
    decision = decide_detector(_cap("astp.http-posture.v1"), _context())
    assert decision.allowed and decision.code is DetectorDecisionCode.ALLOWED


def test_positive_budget_allows_capability_to_run_with_reduced_ceiling():
    capability = _cap("astp.http-observation-field.v1")

    decision = decide_detector(capability, _context(remaining_requests=1))

    assert capability.maximum_default_requests == 30
    assert decision.allowed and decision.code is DetectorDecisionCode.ALLOWED


def test_zero_budget_remains_fail_closed():
    decision = decide_detector(
        _cap("astp.http-observation-field.v1"), _context(remaining_requests=0)
    )

    assert not decision.allowed
    assert decision.code is DetectorDecisionCode.BLOCKED_BUDGET


def test_explicit_and_general_denials_propagate():
    capability = _cap("astp.http-posture.v1")
    assert (
        decide_detector(capability, _context(disposition=MentionDisposition.EXPLICITLY_DENIED)).code
        is DetectorDecisionCode.EXPLICITLY_DENIED
    )
    assert (
        decide_detector(
            capability, _context(applicable_general_denials=("automated scanners prohibited",))
        ).code
        is DetectorDecisionCode.EXPLICITLY_DENIED
    )


def test_runtime_inventory_never_claims_scaffolding_is_field_ready():
    nuclei = _cap("nuclei.exposure-safe.v1")
    assert nuclei.runtime_state is RuntimeState.UNAVAILABLE
    assert not nuclei.field_ready and not nuclei.nightly_enabled


def test_nuclei_classifier_uses_operational_risk_not_severity():
    assert (
        classify_nuclei_template(NucleiTemplateMetadata(template_id="safe"))
        is TemplateRisk.SAFE_READ_ONLY
    )
    assert (
        classify_nuclei_template(NucleiTemplateMetadata(template_id="dos", dos_marker=True))
        is TemplateRisk.PROHIBITED
    )
    assert (
        classify_nuclei_template(NucleiTemplateMetadata(template_id="oast", oast=True))
        is TemplateRisk.REVIEW_REQUIRED
    )


def test_tool_compilers_are_bounded_and_arbitrary_args_impossible():
    job = BoundedToolJob(
        engine=ToolEngine.SQLMAP,
        profile="detect-bounded",
        target="https://example.test/?id=1",
        permit_id="p",
        action_id="a",
        parameter="id",
        max_requests=10,
        max_concurrency=1,
        rate_per_second=1,
        timeout_seconds=30,
    )
    argv = compile_tool_argv(job)
    assert "--batch" in argv and "--risk=1" in argv
    assert not any(term in argv for term in ("--dump", "--os-shell", "--file-read"))
    with pytest.raises(ValueError, match="arbitrary"):
        reject_arbitrary_arguments(("--os-shell",))


def test_secret_detector_redacts_and_hashes_without_proving_validity():
    signals = analyze_exposed_content(b'const key="AKIAABCDEFGHIJKLMNOP";')
    aws = next(item for item in signals if item.kind is SecretKind.AWS_ACCESS_KEY)
    assert "AKIAABCDEFGHIJKLMNOP" not in aws.redacted_value
    assert len(aws.value_sha256) == 64 and not aws.valid_secret_proven
    benign = analyze_exposed_content(b"abcdefghijklmnopqrstuvwxyz012345")
    assert not any(item.confidence >= 0.7 for item in benign)


@pytest.mark.parametrize(
    ("value", "kind"),
    [
        ("AKIAABCDEFGHIJKLMNOP", SecretKind.AWS_ACCESS_KEY),
        ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123", SecretKind.JWT),
        ("api_key=sk_test_abcdefghijklmnopqrstuvwxyz123456", SecretKind.GENERIC_TOKEN),
        ("postgres://app:secret-password@db.example/app", SecretKind.DATABASE_URL),
        ("-----BEGIN PRIVATE KEY-----", SecretKind.PRIVATE_KEY),
    ],
)
def test_secret_acceptance_fixtures_never_emit_complete_value(value, kind):
    signals = analyze_exposed_content(value.encode())
    signal = next(item for item in signals if item.kind is kind)
    serialized = signal.model_dump_json()
    assert value not in serialized
    assert len(signal.value_sha256) == 64


def test_benign_high_entropy_fixture_is_not_promoted():
    signals = analyze_exposed_content(b"sha256=0123456789abcdef0123456789abcdef")
    assert not any(item.confidence >= 0.7 for item in signals)


def test_bounded_discovery_never_authorizes_new_targets():
    result = discover_bounded(
        "https://example.test/", '<a href="/api/users?id=1">x</a>', max_candidates=10
    )
    item = next(row for row in result.hints if "/api/users" in row.target)
    assert item.parameters == ("id",) and item.requires_policy_replanning and not item.executable
    assert len(deterministic_wordlist({"wordpress"})) < 20


def test_idor_requires_ownership_semantics_not_status_difference_only():
    weak = compare_identity_observations(
        IdentityObservation(identity_ref="a", status_code=200, body="one"),
        IdentityObservation(identity_ref="b", status_code=403, body="no"),
    )
    assert weak.state is ProofStateV2.CANDIDATE
    proof = compare_identity_observations(
        IdentityObservation(
            identity_ref="a", status_code=200, body='{"email":"a@x"}', expected_owner=False
        ),
        IdentityObservation(identity_ref="b", status_code=403, expected_owner=True),
    )
    assert proof.state is ProofStateV2.CONFIRMED and "a" not in proof.identity_hashes


def test_auth_workflow_blocks_missing_identity_and_cleanup():
    plan = AuthWorkflowPlan(
        kind=AuthWorkflowKind.LOGOUT_INVALIDATION,
        target="https://example.test/logout",
        state_changing=True,
    )
    assert len(plan.blockers()) == 2


def test_oast_callback_requires_exact_payload_correlation():
    provider = LocalFakeOastProvider()
    payload = provider.issue(
        program_id="p",
        target="https://example.test/",
        action_id="a",
        permit_id="permit",
        detector_id="ssrf",
    )
    wrong = OastCallback(
        payload_id="wrong", protocol="dns", received_at=datetime.now(UTC), source_hash="x"
    )
    assert not correlate_oast(payload, wrong).matched
    assert (
        correlate_oast(payload, provider.record_callback(payload.payload_id, "dns")).state
        is ProofStateV2.CONFIRMED
    )
