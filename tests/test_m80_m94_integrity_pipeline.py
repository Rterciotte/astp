from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from astp.assessment import AssessmentResult
from astp.assessment_checkpoint import create_checkpoint, verify_checkpoint
from astp.assessment_manifest import build_assessment_manifest, verify_assessment_manifest
from astp.confidence import fuse_probabilities
from astp.dedicated_verifiers import verify_cors_headers
from astp.finding_pipeline import CandidatePipelineResult
from astp.findings import CorrelatedFinding, FindingCandidate, FindingSet, FindingSignal, ProofState
from astp.fingerprint import TechnologyFingerprint
from astp.javascript_inventory import inventory_javascript
from astp.lineage import build_assessment_lineage
from astp.network_capabilities import builtin_network_capabilities
from astp.observation import HttpObservationEvidence
from astp.operator_review import ReviewDecision, record_operator_review
from astp.portable_assessment import export_portable_assessment, verify_portable_assessment
from astp.report_bundle import create_report_bundle, verify_report_bundle
from astp.review_package import build_review_package
from astp.risk_context import AssetImportance, Exposure, RiskContext, score_finding_context
from astp.secret_broker import SecretKind, build_secret_reference
from astp.signal_normalizer import NormalizedSignal, NormalizedSignalClass
from astp.verification_plan import FindingVerificationPlan
from astp.verification_queue import enqueue_verification, list_verification_queue
from astp.worker_job import prepare_worker_job


def _evidence(**updates: object) -> HttpObservationEvidence:
    payload = {
        "evidence_id": "e-1",
        "action_id": "a-1",
        "permit_id": "p-1",
        "engagement_id": "eng-1",
        "test_id": "observation.http",
        "observed_at": datetime.now(UTC),
        "method": "GET",
        "target": "https://example.com/",
        "status_code": 200,
        "response_headers": {},
        "content_type": "text/html",
        "body_bytes_captured": 1,
        "body_sha256": "0" * 64,
        "body_preview": "<html></html>",
        "evidence_hash": "1" * 64,
    }
    payload.update(updates)
    return HttpObservationEvidence.model_validate(payload)


def _assessment() -> AssessmentResult:
    signal = NormalizedSignal(
        key="protocol.review",
        signal_class=NormalizedSignalClass.SECURITY_REVIEW,
        evidence_id="e-1",
        target="https://example.com/",
        observation="review",
        confidence=0.7,
    )
    finding = CorrelatedFinding(
        id="finding-1",
        vulnerability="protocol.review",
        asset="https://example.com/",
        proof_state=ProofState.LIKELY,
        signals=[FindingSignal(sensor="protocol", evidence_id="e-1", observation="review")],
        created_at=datetime.now(UTC),
    )
    return AssessmentResult(
        session_id="session-1",
        fingerprints=[TechnologyFingerprint(target="https://example.com/", evidence_ids=["e-1"])],
        signals=[signal],
        candidates=CandidatePipelineResult(candidates=[], suppressed=[]),
        findings=FindingSet(findings=[finding]),
        report_markdown="# report\n",
    )


def test_m80_confidence_fusion_is_bounded() -> None:
    assert fuse_probabilities([0.5, 0.5]) == 0.75
    assert fuse_probabilities([2.0, -1.0]) == 1.0


def test_m81_javascript_inventory_uses_stored_preview_only() -> None:
    evidence = _evidence(body_preview='<script src="/app.js"></script>')
    inventory = inventory_javascript(evidence)
    assert inventory.artifacts[0].url == "https://example.com/app.js"
    assert inventory.artifacts[0].requires_new_permit is True
    assert inventory.network_execution_performed is False


def test_m82_network_capabilities_require_permits() -> None:
    capabilities = builtin_network_capabilities()
    assert len(capabilities) == 2
    assert all(row.requires_execution_permit for row in capabilities)
    assert all(not row.arbitrary_network for row in capabilities)


def test_m83_secret_reference_rejects_inline_tokens() -> None:
    ref = build_secret_reference(SecretKind.API_TOKEN, "env", "ASTP_API_TOKEN")
    assert ref.exportable is False
    try:
        build_secret_reference(SecretKind.API_TOKEN, "env", "token=secret")
    except ValueError:
        pass
    else:
        raise AssertionError("raw secret locator should be rejected")


def test_m84_dedicated_cors_verifier_caps_at_likely() -> None:
    evidence = _evidence(
        response_headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
    )
    candidate = FindingCandidate(
        vulnerability="protocol.cors_wildcard_credentials",
        asset=evidence.target,
        signals=[FindingSignal(sensor="protocol", evidence_id="e-1", observation="cors")],
    )
    result = verify_cors_headers(candidate, {"e-1": evidence})
    assert result.valid is True
    assert result.maximum_supported_state == ProofState.LIKELY


def test_m85_verification_queue_is_durable_and_review_gated(tmp_path: Path) -> None:
    finding = _assessment().findings.findings[0]
    plan = FindingVerificationPlan(
        finding_key=f"{finding.vulnerability}:{finding.asset}",
        current_state=ProofState.SUSPECTED,
        target_state=ProofState.LIKELY,
        steps=[],
    )
    database = tmp_path / "verification.db"
    item = enqueue_verification(database, finding, plan)
    assert item.status.value == "review_required"
    assert list_verification_queue(database)[0].id == item.id


def test_m86_checkpoint_integrity() -> None:
    checkpoint = create_checkpoint("s", "e", "digest", completed_evidence_ids=["e-1"])
    assert verify_checkpoint(checkpoint)
    tampered = checkpoint.model_copy(update={"policy_digest": "other"})
    assert not verify_checkpoint(tampered)


def test_m87_lineage_connects_evidence_signal_finding_report() -> None:
    lineage = build_assessment_lineage(_assessment())
    kinds = {node.kind.value for node in lineage.nodes}
    assert {"evidence", "signal", "finding", "report"} <= kinds


def test_m88_risk_score_is_explicitly_not_cvss() -> None:
    finding = _assessment().findings.findings[0]
    score = score_finding_context(
        finding,
        RiskContext(exposure=Exposure.INTERNET, asset_importance=AssetImportance.HIGH),
    )
    assert score.score > 0
    assert score.is_cvss is False


def test_m89_report_bundle_integrity(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    result = tmp_path / "result.yaml"
    report.write_text("report", encoding="utf-8")
    result.write_text("result", encoding="utf-8")
    bundle = tmp_path / "bundle.zip"
    manifest = create_report_bundle(bundle, report_path=report, structured_result_path=result)
    assert len(manifest.files) == 2
    assert verify_report_bundle(bundle)


def test_m90_worker_job_contains_no_signing_key_authority() -> None:
    job = prepare_worker_job("http.observation.v1", "https://example.com", "a", "p", "evidence")
    assert job.signing_keys_included is False
    assert job.arbitrary_mounts_allowed is False
    assert job.arbitrary_network_allowed is False


def test_m91_assessment_manifest_detects_tampering() -> None:
    manifest = build_assessment_manifest(_assessment())
    assert verify_assessment_manifest(manifest)
    tampered = manifest.model_copy(update={"report_sha256": "0" * 64})
    assert not verify_assessment_manifest(tampered)


def test_m92_operator_review_binds_manifest() -> None:
    manifest = build_assessment_manifest(_assessment())
    review = record_operator_review(manifest, "operator", ReviewDecision.APPROVE)
    assert review.assessment_manifest_hash == manifest.manifest_hash


def test_m93_portable_assessment_integrity(tmp_path: Path) -> None:
    result = _assessment()
    manifest = build_assessment_manifest(result)
    review = record_operator_review(manifest, "operator", ReviewDecision.APPROVE)
    report = tmp_path / "report.md"
    structured = tmp_path / "assessment.yaml"
    report.write_text(result.report_markdown, encoding="utf-8")
    structured.write_text("schema_version: '1'\n", encoding="utf-8")
    archive = tmp_path / "assessment.zip"
    export_portable_assessment(
        archive,
        manifest=manifest,
        review=review,
        report_path=report,
        result_path=structured,
    )
    assert verify_portable_assessment(archive)


def test_m94_review_package_is_offline_and_integrity_bound(tmp_path: Path) -> None:
    package = build_review_package(_assessment(), tmp_path / "review")
    assert package.network_execution_performed is False
    assert package.report_path.exists()
    assert package.result_path.exists()
    assert verify_assessment_manifest(package.manifest)
