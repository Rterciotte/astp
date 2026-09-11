from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from astp.authorization import AuthorizationRequest
from astp.detector_execution import (
    DetectorAccounting,
    DetectorAdapterError,
    DetectorAdapterResult,
    DetectorArtifacts,
    DetectorExecutionRequest,
    DetectorExecutionService,
    DetectorRunStatus,
)
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.models import (
    Engagement,
    OperationalStatus,
    ProgramBinding,
    ProgramOperationalAttestation,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as RuntimeTestDefinition,
)
from astp.nightly_campaign import ServiceNightlyDetectorExecutor
from astp.operational_lease import OperationalLeaseStore
from astp.orchestrator import (
    OrchestratorDetectorJournal,
    run_orchestrator_execution,
    start_orchestrator,
)
from astp.orchestrator_manifest import CampaignManifest, verify_campaign_manifest
from astp.orchestrator_models import AutonomousCampaignConfig
from astp.orchestrator_scheduler import rank_opportunity
from astp.orchestrator_store import OrchestratorStore
from astp.permits import issue_execution_permit
from astp.proof_model import ProofStateV2


@dataclass
class FakeAdapter:
    detector_ids: frozenset[str]
    calls: int = 0
    fail: DetectorAdapterError | None = None
    permit_max_requests: int | None = None
    permit_expires_at: datetime | None = None

    def execute(self, request, permit, run_root: Path) -> DetectorAdapterResult:
        self.calls += 1
        self.permit_max_requests = permit.payload.max_requests
        self.permit_expires_at = permit.payload.expires_at
        assert (run_root / "authorization.json").exists()
        assert permit.payload.detector_run_id
        if self.fail:
            raise self.fail
        return DetectorAdapterResult(
            accounting=DetectorAccounting(attempted=1, forwarded=1, responses=1),
            artifacts=DetectorArtifacts(worker_receipt={"requests": 99}),
            proof_state=ProofStateV2.REPRODUCED,
            requirement_satisfied=True,
            candidate_id="candidate-1",
        )


def _request(**changes) -> DetectorExecutionRequest:
    detector = next(
        row for row in builtin_detector_registry() if row.detector_id == "nuclei.astp-lab-cve.v1"
    )
    context = DetectorPolicyContext(
        disposition=MentionDisposition.EXPLICITLY_ALLOWED,
        target_in_scope=True,
        remaining_requests=10,
    )
    opportunity = rank_opportunity(
        detector,
        program_id="program-1",
        target="http://target.test/cve",
        signals=("version",),
        decision=decide_detector(detector, context),
        remaining_budget=10,
    )
    values = {
        "campaign_id": "campaign-1",
        "campaign_active": True,
        "program_id": "program-1",
        "program_revision": "revision-1",
        "current_program_revision": "revision-1",
        "target": "http://target.test/cve",
        "opportunity": opportunity,
        "detector": detector,
        "runtime_id": "nuclei",
        "runtime_digest": "sha256:qualified",
        "runtime_qualification_digest": "sha256:qualified",
        "engagement": Engagement(id="engagement-1", name="Local", scope=ScopePolicy()),
        "target_in_scope": True,
        "semantic_review_complete": True,
        "policy_context": context,
        "global_remaining": 10,
        "program_remaining": 10,
        "detector_remaining": 10,
        "max_rps": 1.0,
        "proof_requirement": detector.proof_requirement,
    }
    values.update(changes)
    return DetectorExecutionRequest(**values)


def test_execution_persists_authorization_result_and_proxy_accounting(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(tmp_path, "test-signing-key", (adapter,))

    result = service.execute(_request(), now=datetime(2026, 1, 1, tzinfo=UTC))

    assert result.status is DetectorRunStatus.COMPLETED
    assert result.accounting.forwarded == 1
    assert result.artifacts.worker_receipt["requests"] == 99  # telemetry is not authoritative
    assert adapter.calls == 1
    run_root = tmp_path / "runs" / result.detector_run_id
    assert (run_root / "authorization.json").exists()
    assert (run_root / "result.json").exists()
    with sqlite3.connect(tmp_path / "detector-budgets.db") as db:
        assert db.execute("SELECT consumed,state FROM reservations").fetchone() == (1, "committed")


def test_stale_revision_blocks_before_adapter_and_reservation(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(tmp_path, "test-signing-key", (adapter,))

    result = service.execute(_request(current_program_revision="revision-2"))

    assert result.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert adapter.calls == 0
    with sqlite3.connect(tmp_path / "detector-budgets.db") as db:
        assert db.execute("SELECT count(*) FROM reservations").fetchone()[0] == 0


def test_execution_reduces_permit_to_single_remaining_request(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(tmp_path, "test-signing-key", (adapter,))
    context = DetectorPolicyContext(target_in_scope=True, remaining_requests=1)
    request = _request(
        policy_context=context,
        global_remaining=1,
        program_remaining=1,
        detector_remaining=1,
    )

    result = service.execute(request)

    assert result.status is DetectorRunStatus.COMPLETED
    assert result.authorization is not None
    assert result.authorization.payload.max_requests == 1
    assert adapter.permit_max_requests == 1


def test_forwarded_without_response_is_unknown_and_never_retryable(tmp_path) -> None:
    accounting = DetectorAccounting(attempted=1, forwarded=1, responses=0, unknown_outcomes=1)
    adapter = FakeAdapter(
        frozenset({"nuclei.astp-lab-cve.v1"}),
        fail=DetectorAdapterError(
            "worker_crash", accounting=accounting, network_started=True, retryable=True
        ),
    )
    service = DetectorExecutionService(tmp_path, "test-signing-key", (adapter,))

    result = service.execute(_request())

    assert result.status is DetectorRunStatus.UNKNOWN_OUTCOME
    assert not result.retryable
    with sqlite3.connect(tmp_path / "detector-budgets.db") as db:
        assert db.execute("SELECT consumed,state FROM reservations").fetchone() == (
            1,
            "unknown_outcome",
        )


def test_retry_attempt_gets_fresh_run_and_permit(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(tmp_path, "test-signing-key", (adapter,))

    first = service.execute(_request(execution_attempt=1))
    second = service.execute(_request(execution_attempt=2))

    assert first.detector_run_id != second.detector_run_id
    assert first.authorization.payload.permit_id != second.authorization.payload.permit_id


def test_shared_service_projects_full_action_lifecycle_into_orchestrator(tmp_path) -> None:
    campaign_root = tmp_path / "campaign"
    start_orchestrator(
        AutonomousCampaignConfig(
            campaign_id="campaign-1",
            selected_program_ids=("program-1",),
            dry_run=False,
            execute=True,
        ),
        campaign_root,
    )
    store = OrchestratorStore(campaign_root / "campaign.db")
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(
        campaign_root, "test-signing-key", (adapter,), OrchestratorDetectorJournal(store)
    )

    result = service.execute(_request())
    snapshot = store.snapshot("campaign-1")

    assert result.status is DetectorRunStatus.COMPLETED
    assert snapshot["actions"][0]["state"] == "completed"
    assert snapshot["counters"]["detector_runs_started"] == 1
    assert snapshot["counters"]["detector_runs_completed"] == 1
    assert snapshot["counters"]["requests_forwarded"] == 1
    assert snapshot["counters"]["permits_issued"] == 1
    assert snapshot["counters"]["permits_consumed"] == 1


def test_execute_runner_uses_service_and_finalizes_report_and_manifest(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    config = AutonomousCampaignConfig(
        campaign_id="campaign-1",
        selected_program_ids=("program-1",),
        dry_run=False,
        execute=True,
    )

    snapshot, results = run_orchestrator_execution(
        config,
        tmp_path,
        requests=(_request(),),
        adapters=(adapter,),
        signing_key="test-signing-key",
    )

    assert results[0].status is DetectorRunStatus.COMPLETED
    assert snapshot["campaign"]["state"] == "completed"
    assert (tmp_path / "campaign-report.md").exists()
    manifest_path = tmp_path / "campaign-manifest.json"
    manifest = CampaignManifest.model_validate_json(manifest_path.read_text())
    assert verify_campaign_manifest(manifest, tmp_path)
    assert any(name.endswith("authorization.json") for name in manifest.artifacts)
    assert any(name.endswith("result.json") for name in manifest.artifacts)


def test_nightly_executor_delegates_to_detector_execution_service(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(tmp_path, "test-signing-key", (adapter,))
    nightly = ServiceNightlyDetectorExecutor(service, lambda _item, _engagement: _request())

    outcome = nightly.execute(object(), object())

    assert adapter.calls == 1
    assert outcome.forwarded == 1
    assert outcome.responses == 1
    assert outcome.evidence_id is None


def test_verifier_request_starts_from_candidate_proof(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(tmp_path, "test-signing-key", (adapter,))

    result = service.execute(_request(parent_candidate_id="candidate-parent"))

    assert result.proof_before is ProofStateV2.CANDIDATE


def test_lease_is_revalidated_immediately_before_adapter_launch(tmp_path) -> None:
    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(
        tmp_path,
        "test-signing-key",
        (adapter,),
        lease_validator=lambda _request: False,
    )

    result = service.execute(_request())

    assert result.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert result.failure_category == "lease_revoked_before_launch"
    assert result.authorization is not None
    assert result.accounting.forwarded == 0
    assert adapter.calls == 0


def test_real_durable_lease_is_required_revalidated_and_caps_detector_permit(tmp_path) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    engagement = Engagement(
        id="engagement-operational",
        name="Local operational program",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="target.test")]),
        program=ProgramBinding(
            program_id="program-1",
            platform="local-bughunt",
            source_content_sha256="a" * 64,
            requires_online=True,
        ),
    )
    attestation = ProgramOperationalAttestation(
        id="attestation-1",
        program_id="program-1",
        source_content_sha256="a" * 64,
        status=OperationalStatus.ONLINE,
        observed_at=now,
        source_type="local_fixture",
    )
    store_path = tmp_path / "leases.json"
    store = OperationalLeaseStore(store_path)
    lease = store.issue(
        engagement,
        attestation,
        assessment_id="assessment-1",
        preflight_report_hash="preflight-1",
        valid_from=now,
        ttl_seconds=30,
    )
    test = RuntimeTestDefinition(
        id="test-operational",
        title="Local observation",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
    )
    signing_key = "test-signing-key-with-at-least-32-bytes"
    execution_permit = issue_execution_permit(
        engagement,
        test,
        AuthorizationRequest(
            target="http://target.test/cve",
            http_method="GET",
            requested_requests_per_second=1,
            program_operational_attestation=attestation,
            program_operational_lease=lease,
            operational_lease_store_path=str(store_path),
            now=now,
        ),
        signing_key,
        now=now,
    )
    request = _request(
        engagement=engagement,
        test_definition=test,
        execution_permit=execution_permit,
        operational_attestation=attestation,
        operational_lease=lease,
        operational_lease_store_path=str(store_path),
    )
    missing_adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    missing = DetectorExecutionService(
        tmp_path / "missing-permit", signing_key, (missing_adapter,)
    ).execute(request.model_copy(update={"execution_permit": None}), now=now)
    assert missing.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert missing.authorization is None
    assert missing_adapter.calls == 0

    adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    service = DetectorExecutionService(tmp_path / "valid", signing_key, (adapter,))

    result = service.execute(request, now=now)

    assert result.status is DetectorRunStatus.COMPLETED
    assert adapter.permit_expires_at == lease.valid_until

    store.revoke(lease.id)
    blocked_adapter = FakeAdapter(frozenset({"nuclei.astp-lab-cve.v1"}))
    blocked = DetectorExecutionService(
        tmp_path / "revoked", signing_key, (blocked_adapter,)
    ).execute(request, now=now)
    assert blocked.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert blocked.authorization is None
    assert blocked_adapter.calls == 0
