from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from astp.artifact_planner import plan_javascript_artifacts
from astp.assessment_checkpoint import create_checkpoint
from astp.assessment_resume import evaluate_assessment_resume
from astp.capability_evidence import derive_network_capability_evidence
from astp.capability_scheduler import round_robin_capabilities
from astp.closure_gate import evaluate_closure
from astp.evidence_quarantine import list_quarantined_evidence, quarantine_evidence
from astp.findings import CorrelatedFinding, FindingSignal, ProofState
from astp.javascript_inventory import JavaScriptArtifact, JavaScriptInventory
from astp.js_static_analysis import analyze_javascript_text
from astp.observation import HttpObservationEvidence
from astp.operator_review import OperatorReview, ReviewDecision
from astp.publication_bundle import build_publication_bundle, verify_publication_bundle
from astp.readiness import evaluate_assessment_readiness
from astp.report_finalization import ReportFinalization
from astp.risk_context import AssetImportance, Exposure, RiskContext
from astp.risk_fusion import fuse_finding_risk
from astp.session_journal import append_session_event, verify_session_journal
from astp.transport import ResolvedEndpoint
from astp.verification_broker import broker_reviewed_verification
from astp.verification_plan import FindingVerificationPlan
from astp.verification_queue import VerificationQueueItem, VerificationQueueStatus
from astp.verification_review import (
    VerificationReviewDecision,
    review_verification_item,
)
from astp.worker_job import WorkerJobStatus, prepare_worker_job
from astp.worker_receipt import create_worker_receipt, verify_worker_receipt
from astp.worker_repository import load_worker_job, store_worker_job, update_worker_job_status


def _http_evidence() -> HttpObservationEvidence:
    return HttpObservationEvidence(
        evidence_id="e-transport",
        action_id="a-transport",
        permit_id="p-transport",
        engagement_id="eng-1",
        test_id="observation.http",
        observed_at=datetime.now(UTC),
        method="GET",
        target="https://example.com/",
        status_code=200,
        response_headers={},
        body_sha256="0" * 64,
        evidence_hash="1" * 64,
        resolved_endpoint=ResolvedEndpoint(
            hostname="example.com",
            port=443,
            addresses=("93.184.216.34",),
            connected_address="93.184.216.34",
            tls_protocol="TLSv1.3",
            tls_cipher="TLS_AES_256_GCM_SHA384",
            peer_certificate_sha256="2" * 64,
        ),
    )


def _verification_item() -> VerificationQueueItem:
    plan = FindingVerificationPlan(
        finding_key="cors:https://example.com/",
        current_state=ProofState.SUSPECTED,
        target_state=ProofState.LIKELY,
        steps=[],
    )
    return VerificationQueueItem(
        id="verify-finding-1",
        finding_id="finding-1",
        status=VerificationQueueStatus.REVIEW_REQUIRED,
        plan=plan,
        created_at=datetime.now(UTC),
    )


def _finding() -> CorrelatedFinding:
    return CorrelatedFinding(
        id="finding-1",
        vulnerability="protocol.review",
        asset="https://example.com/",
        proof_state=ProofState.LIKELY,
        signals=[FindingSignal(sensor="test", evidence_id="e-1", observation="review")],
        created_at=datetime.now(UTC),
    )


def test_m95_derives_dns_and_tls_from_stored_transport_evidence() -> None:
    dns, tls = derive_network_capability_evidence(_http_evidence())
    assert dns is not None and dns.addresses == ["93.184.216.34"]
    assert tls is not None and tls.protocol == "TLSv1.3"


def test_m96_static_javascript_analysis_is_offline_and_non_confirming() -> None:
    result = analyze_javascript_text(
        'const endpoint="/api/v1/me"; window.__NEXT_DATA__={}; //# sourceMappingURL=app.js.map'
    )
    assert result.network_performed is False
    assert len(result.signals) >= 3
    assert all(not signal.vulnerability_confirmed for signal in result.signals)


def test_m97_artifact_plan_requires_new_permits() -> None:
    inventory = JavaScriptInventory(
        target="https://example.com/",
        artifacts=[
            JavaScriptArtifact(
                url="https://example.com/app.js",
                evidence_id="e-1",
                source="html.script.src",
                same_origin_hint=True,
            )
        ],
    )
    plan = plan_javascript_artifacts(inventory)
    assert len(plan.items) == 1
    assert plan.items[0].requires_new_permit is True
    assert plan.network_performed is False


def test_m98_verification_review_is_hash_bound() -> None:
    item = _verification_item()
    review = review_verification_item(
        item,
        "operator",
        VerificationReviewDecision.APPROVE_FOR_AUTHORIZATION,
    )
    assert review.queue_item_id == item.id
    assert len(review.queue_item_hash) == 64


def test_m99_verification_broker_still_requires_policy_and_permit() -> None:
    item = _verification_item()
    review = review_verification_item(
        item,
        "operator",
        VerificationReviewDecision.APPROVE_FOR_AUTHORIZATION,
    )
    candidate = broker_reviewed_verification(item, review)
    assert candidate.requires_policy_authorization is True
    assert candidate.requires_fresh_permit is True
    assert candidate.execution_performed is False


def test_m100_worker_job_repository_is_durable(tmp_path: Path) -> None:
    database = tmp_path / "worker.db"
    job = prepare_worker_job("http.observation.v1", "https://example.com", "a", "p", "e")
    store_worker_job(database, job)
    update_worker_job_status(database, job.id, WorkerJobStatus.DISPATCHED)
    loaded, status = load_worker_job(database, job.id)
    assert loaded.id == job.id
    assert status == WorkerJobStatus.DISPATCHED


def test_m101_worker_receipt_is_bound_to_job_action_and_permit() -> None:
    job = prepare_worker_job("http.observation.v1", "https://example.com", "a", "p", "e")
    receipt = create_worker_receipt(job, success=True, evidence_id="evidence-1")
    assert verify_worker_receipt(job, receipt)
    assert not verify_worker_receipt(job.model_copy(update={"permit_id": "other"}), receipt)


def test_m102_capability_scheduler_round_robins_capabilities() -> None:
    jobs = [
        prepare_worker_job("tls.handshake.v1", "https://b.example", "a2", "p2", "e2"),
        prepare_worker_job("dns.lookup.v1", "https://a.example", "a1", "p1", "e1"),
        prepare_worker_job("dns.lookup.v1", "https://c.example", "a3", "p3", "e3"),
    ]
    schedule = round_robin_capabilities(jobs)
    lookup = {job.id: job.capability_id for job in jobs}
    assert [lookup[job_id] for job_id in schedule.job_ids[:2]] == [
        "dns.lookup.v1",
        "tls.handshake.v1",
    ]


def test_m103_resume_rejects_policy_drift() -> None:
    checkpoint = create_checkpoint("session", "eng", "digest")
    decision = evaluate_assessment_resume(
        checkpoint,
        engagement_id="eng",
        current_policy_digest="different",
    )
    assert decision.allowed is False
    assert decision.requires_replan is True


def test_m104_quarantine_is_durable(tmp_path: Path) -> None:
    database = tmp_path / "quarantine.db"
    quarantine_evidence(database, "e-bad", "hash mismatch")
    rows = list_quarantined_evidence(database)
    assert rows[0].evidence_id == "e-bad"
    assert rows[0].reason == "hash mismatch"


def test_m105_risk_fusion_does_not_claim_cvss() -> None:
    result = fuse_finding_risk(
        _finding(),
        RiskContext(exposure=Exposure.INTERNET, asset_importance=AssetImportance.HIGH),
        confidence=0.8,
    )
    assert result.fused_score > 0
    assert result.is_cvss is False


def test_m106_finalization_model_can_mark_approved_report_publishable() -> None:
    finalization = ReportFinalization(
        manifest_hash="a" * 64,
        review_decision=ReviewDecision.APPROVE,
        report_sha256="b" * 64,
        finalized_at=datetime.now(UTC),
        publishable=True,
    )
    assert finalization.publishable is True


def test_m107_publication_bundle_requires_publishable_finalization(tmp_path: Path) -> None:
    artifact = tmp_path / "report.md"
    artifact.write_text("report", encoding="utf-8")
    finalization = ReportFinalization(
        manifest_hash="a" * 64,
        review_decision=ReviewDecision.APPROVE,
        report_sha256="b" * 64,
        finalized_at=datetime.now(UTC),
        publishable=True,
    )
    archive = tmp_path / "publication.zip"
    build_publication_bundle(archive, finalization, [artifact])
    assert verify_publication_bundle(archive)


def test_m108_session_journal_detects_tampering(tmp_path: Path) -> None:
    journal = tmp_path / "journal.jsonl"
    append_session_event(journal, "session-1", "started")
    append_session_event(journal, "session-1", "completed")
    assert verify_session_journal(journal)
    journal.write_text(journal.read_text(encoding="utf-8").replace("completed", "changed"))
    assert not verify_session_journal(journal)


def test_m109_readiness_requires_every_blocking_prerequisite() -> None:
    blocked = evaluate_assessment_readiness(
        policy_ready=True,
        attestation_fresh=False,
        permit_keys_configured=True,
        evidence_store_ready=True,
        worker_contracts_ready=True,
    )
    assert blocked.ready is False
    ready = evaluate_assessment_readiness(
        policy_ready=True,
        attestation_fresh=True,
        permit_keys_configured=True,
        evidence_store_ready=True,
        worker_contracts_ready=True,
    )
    assert ready.ready is True


def test_m110_closure_gate_requires_cleared_verification_and_quarantine() -> None:
    review = OperatorReview(
        assessment_manifest_hash="a" * 64,
        reviewer="operator",
        decision=ReviewDecision.APPROVE,
        reviewed_at=datetime.now(UTC),
    )
    finalization = ReportFinalization(
        manifest_hash="a" * 64,
        review_decision=ReviewDecision.APPROVE,
        report_sha256="b" * 64,
        finalized_at=datetime.now(UTC),
        publishable=True,
    )
    blocked = evaluate_closure(
        review,
        finalization,
        unresolved_verifications=1,
        quarantined_evidence=0,
    )
    assert blocked.closable is False
    clear = evaluate_closure(
        review,
        finalization,
        unresolved_verifications=0,
        quarantined_evidence=0,
    )
    assert clear.closable is True
