from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from astp.browser_intake import BrowserCapture
from astp.detector_execution import DetectorExecutionRequest
from astp.detector_policy import DetectorPolicyContext, decide_detector
from astp.detector_registry import DetectorCapability
from astp.models import OperationalStatus, ProgramOperationalAttestation, RiskClass, TestDefinition
from astp.operational_lease import OperationalLeaseStore
from astp.orchestrator_scheduler import rank_opportunity
from astp.permit_broker import PermitBrokerReceipt, broker_queue_item_permit
from astp.planner import TargetSemanticAssessment, build_observation_plan
from astp.program_catalog import (
    BugBountyWorkspace,
    discover_programs,
    merge_discovery,
    sync_program_capture,
)
from astp.program_intake import compile_program
from astp.target_discovery import CandidateKind, CandidateSafety, TargetCandidate
from astp.target_registry import RegistryEntry, TargetRegistry
from astp.work_queue import build_fair_work_queue


def derive_local_authorized_detector_request(
    *,
    root: Path,
    campaign_id: str,
    listing_capture: BrowserCapture,
    detail_capture: BrowserCapture,
    target: str,
    detector: DetectorCapability,
    runtime_digest: str,
    signing_key: str | bytes,
    now: datetime | None = None,
) -> tuple[DetectorExecutionRequest, PermitBrokerReceipt]:
    """Derive one detector request through the real local intake and policy chain."""
    current = now or datetime.now(UTC)
    discovery = discover_programs(listing_capture, platform="local-bughunt")
    if len(discovery.candidates) != 1:
        raise ValueError("local authorization acceptance requires exactly one discovered program")
    workspace = merge_discovery(
        BugBountyWorkspace(platform="local-bughunt", source_url=listing_capture.url), discovery
    )
    candidate = discovery.candidates[0]
    program = sync_program_capture(
        workspace,
        candidate_id=candidate.id,
        capture=detail_capture,
        catalog_path=root / "catalog.yaml",
        captures_dir=root / "captures",
        programs_dir=root / "programs",
    )
    engagement = compile_program(program, max_requests_per_second=1)
    if engagement.program is None or not engagement.program.requires_online:
        raise ValueError("compiled local program must require the operational gate")

    attestation = ProgramOperationalAttestation(
        id=f"attestation-{candidate.id}",
        program_id=engagement.program.program_id,
        source_content_sha256=engagement.program.source_content_sha256,
        status=OperationalStatus.ONLINE,
        observed_at=current,
        source_type="local_fixture",
        source_url=detail_capture.url,
    )
    lease_store_path = root / "operational-leases.json"
    lease = OperationalLeaseStore(lease_store_path).issue(
        engagement,
        attestation,
        assessment_id=campaign_id,
        preflight_report_hash=engagement.program.source_content_sha256,
        valid_from=current,
        ttl_seconds=120,
    )

    target_candidate = TargetCandidate(
        id=f"target-{candidate.id}",
        canonical_target=target,
        display_target=target,
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        requires_new_permit=True,
        requires_semantic_assessment=bool(engagement.constraints.semantic_exclusions),
        executable=False,
        reason="seeded from the exact normalized local program scope",
        provenance=(),
        discovered_at=current,
    )
    registry = TargetRegistry(
        engagement_id=engagement.id,
        updated_at=current,
        entries=[
            RegistryEntry(
                canonical_target=target,
                candidate_ids=[target_candidate.id],
                provenance=[],
                latest_candidate=target_candidate,
                first_seen_at=current,
                last_seen_at=current,
            )
        ],
    )
    test = TestDefinition(
        id=f"test-{detector.detector_id}",
        title="Bounded local detector execution",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
    )
    assessments = {target: TargetSemanticAssessment()}
    plan = build_observation_plan(
        registry,
        engagement,
        test,
        semantic_target_assessments=assessments,
        operational_attestation=attestation,
        operational_lease=lease,
        operational_lease_store_path=str(lease_store_path),
        requested_rps=1,
        now=current,
    )
    queue = build_fair_work_queue([plan], max_active_programs=1, max_items=1, now=current)
    if len(queue.items) != 1:
        raise ValueError("derived policy did not produce one authorizable local action")
    broker = broker_queue_item_permit(
        queue.items[0],
        engagement,
        test,
        signing_key,
        operational_attestation=attestation,
        operational_lease=lease,
        operational_lease_store_path=str(lease_store_path),
        requested_rps=1,
        now=current,
    )
    context = DetectorPolicyContext(
        target_in_scope=True,
        semantic_review_complete=True,
        operational=True,
        remaining_requests=1,
        provenance=(str(root / "catalog.yaml"), str(lease_store_path)),
    )
    opportunity = rank_opportunity(
        detector,
        program_id=engagement.program.program_id,
        target=target,
        signals=("authorized-local-observation",),
        decision=decide_detector(detector, context),
        remaining_budget=1,
    )
    request = DetectorExecutionRequest(
        campaign_id=campaign_id,
        campaign_active=True,
        program_id=engagement.program.program_id,
        program_revision=engagement.program.source_content_sha256,
        current_program_revision=engagement.program.source_content_sha256,
        target=target,
        opportunity=opportunity,
        detector=detector,
        runtime_id=detector.required_runtime or detector.engine,
        runtime_digest=runtime_digest,
        runtime_qualification_digest=runtime_digest,
        engagement=engagement,
        test_definition=test,
        execution_permit=broker.permit,
        operational_attestation=attestation,
        operational_lease=lease,
        operational_lease_store_path=str(lease_store_path),
        target_in_scope=True,
        semantic_review_complete=True,
        policy_context=context,
        global_remaining=1,
        program_remaining=1,
        detector_remaining=1,
        max_rps=1,
        proof_requirement=detector.proof_requirement,
        user_agent=engagement.program.recommended_user_agent or "ASTP local acceptance",
        authorized_path_prefix="/",
    )
    return request, broker
