from datetime import UTC, datetime
from pathlib import Path

from astp.assessment import assess_evidence
from astp.assessment_orchestrator import orchestrate_stored_evidence
from astp.assessment_report import AssessmentReportInput, assemble_assessment_report
from astp.field_validation import validate_assessment_recovery
from astp.finding_pipeline import build_finding_candidates
from astp.finding_repository import get_finding, resolve_finding, set_retest_state, upsert_finding
from astp.findings import CorrelatedFinding, FindingSet, ProofState
from astp.fingerprint import FingerprintKind
from astp.http_fingerprint import fingerprint_http
from astp.models import (
    Constraints,
    Engagement,
    MethodPolicy,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import TestDefinition as RuntimeTestDefinition
from astp.observation import HttpObservationEvidence
from astp.proof_registry import builtin_proof_registry, select_proof_verifier
from astp.protocol_analyzers import analyze_protocol_posture
from astp.signal_normalizer import NormalizedSignalClass, normalize_signals
from astp.target_registry import empty_registry
from astp.web_posture import analyze_http_posture

NOW = datetime.now(UTC)


def engagement() -> Engagement:
    return Engagement(
        id="eng",
        name="Example",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.com")]),
        methods=MethodPolicy(),
        constraints=Constraints(),
    )


def observation_test() -> RuntimeTestDefinition:
    return RuntimeTestDefinition(
        id="test", title="observe", category="web", risk_class=RiskClass.PASSIVE
    )


def evidence(*, body: str = "", headers: dict[str, str] | None = None) -> HttpObservationEvidence:
    row = HttpObservationEvidence(
        evidence_id="e-1",
        action_id="a-1",
        permit_id="p-1",
        engagement_id="eng",
        test_id="test",
        observed_at=NOW,
        method="GET",
        target="https://example.com/",
        status_code=200,
        response_headers=headers or {},
        content_type="text/html",
        body_sha256="0" * 64,
        body_preview=body or None,
        evidence_hash="pending",
    )
    import hashlib

    from astp.observation import _canonical_json

    payload = row.model_dump(mode="json", exclude={"evidence_hash"})
    return row.model_copy(
        update={"evidence_hash": hashlib.sha256(_canonical_json(payload)).hexdigest()}
    )


def test_m69_fingerprint_schema_keeps_evidence_and_confidence():
    result = fingerprint_http(evidence(headers={"Server": "nginx/1.25"}))
    server = next(row for row in result.observations if row.kind == FingerprintKind.SERVER)
    assert server.evidence_id == "e-1"
    assert server.value == "nginx"
    assert server.version == "1.25"
    assert not server.confirmed_vulnerability


def test_m70_http_fingerprinter_extracts_framework_and_scripts():
    result = fingerprint_http(
        evidence(
            body='<meta name="generator" content="WordPress 6"><script src="/jquery.min.js"></script>',
            headers={"X-Powered-By": "PHP/8.3"},
        )
    )
    values = {row.value for row in result.observations}
    assert {"PHP", "WordPress 6", "jQuery"} <= values


def test_m71_protocol_analyzers_remain_nonconfirming():
    result = analyze_protocol_posture(
        evidence(
            headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        )
    )
    assert any(row.name == "cors_wildcard_with_credentials_header" for row in result.signals)
    assert not any(row.confirmed_vulnerability for row in result.signals)


def test_m72_normalization_separates_technology_from_security_review():
    observed = evidence(
        headers={
            "Server": "nginx",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    rows = normalize_signals(
        fingerprint_http(observed),
        analyze_protocol_posture(observed),
        analyze_http_posture(observed),
    )
    assert any(row.signal_class == NormalizedSignalClass.TECHNOLOGY for row in rows)
    assert any(row.signal_class == NormalizedSignalClass.SECURITY_REVIEW for row in rows)


def test_m73_pipeline_does_not_turn_informational_posture_into_findings():
    observed = evidence(headers={"Server": "nginx"})
    rows = normalize_signals(fingerprint_http(observed), analyze_protocol_posture(observed))
    result = build_finding_candidates(rows)
    assert not result.candidates
    assert result.suppressed_signal_keys


def test_m74_registry_requires_dedicated_verifier_for_cors_candidate():
    observed = evidence(
        headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    )
    rows = normalize_signals(fingerprint_http(observed), analyze_protocol_posture(observed))
    candidate = build_finding_candidates(rows).candidates[0]
    spec = select_proof_verifier(candidate, builtin_proof_registry())
    assert spec is not None
    assert not spec.automatic_execution
    assert spec.maximum_state == ProofState.LIKELY


def test_m75_orchestrator_connects_evidence_feedback_and_replanning_without_network():
    observed = evidence(body='<a href="/next">next</a>')
    result = orchestrate_stored_evidence(
        "s1", [observed], empty_registry("eng"), engagement(), observation_test()
    )
    assert result.cycles[0].added_targets == 1
    assert not result.network_execution_performed
    assert result.final_plan is not None


def test_m76_finding_repository_persists_retest_and_resolution(tmp_path: Path):
    finding = CorrelatedFinding(
        id="f-1",
        vulnerability="review",
        asset="example.com",
        proof_state=ProofState.SUSPECTED,
        created_at=NOW,
    )
    db = tmp_path / "findings.db"
    upsert_finding(db, finding)
    assert set_retest_state(db, "f-1", required=True).retest_required
    assert resolve_finding(db, "f-1").status.value == "resolved"
    assert get_finding(db, "f-1").finding.id == "f-1"


def test_m77_report_assembles_fingerprint_findings_and_limitations():
    fingerprint = fingerprint_http(evidence(headers={"Server": "nginx"}))
    report = assemble_assessment_report(
        engagement(),
        AssessmentReportInput(
            fingerprints=[fingerprint],
            findings=FindingSet(),
            limitations=["Browser execution not performed."],
            evidence_ids=["e-1"],
        ),
        now=NOW,
    )
    assert "Technology fingerprint" in report
    assert "nginx" in report
    assert "Browser execution not performed" in report


def test_m78_assessment_runs_fingerprint_to_report_offline():
    result = assess_evidence(
        "s1",
        [evidence(headers={"Server": "nginx"})],
        empty_registry("eng"),
        engagement(),
        observation_test(),
    )
    assert result.fingerprints
    assert "ASTP Assessment Record" in result.report_markdown
    assert not result.network_execution_performed


def test_m79_field_recovery_validation_rejects_no_invariants():
    result = assess_evidence(
        "s1", [evidence()], empty_registry("eng"), engagement(), observation_test()
    )
    validation = validate_assessment_recovery(result)
    assert validation.passed
    assert {row.name for row in validation.checks} == {
        "no_implicit_network",
        "invalid_evidence_quarantined",
        "report_generated",
    }
