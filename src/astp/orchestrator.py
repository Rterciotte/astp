from __future__ import annotations

import json
from pathlib import Path

from astp.detector_execution import (
    DetectorExecutionRequest,
    DetectorExecutionService,
    DetectorRunResult,
    DetectorRunStatus,
    TypedDetectorAdapter,
)
from astp.orchestrator_manifest import build_campaign_manifest
from astp.orchestrator_models import (
    ActionState,
    AutonomousCampaignConfig,
    CampaignReadiness,
    CampaignState,
)
from astp.orchestrator_scheduler import canonical_idempotency_key
from astp.orchestrator_store import OrchestratorStore


class OrchestratorDetectorJournal:
    """Durable projection of the shared detector execution service."""

    def __init__(self, store: OrchestratorStore) -> None:
        self.store = store

    def create_action(self, request: DetectorExecutionRequest, action_id: str) -> None:
        key = canonical_idempotency_key(
            campaign_id=request.campaign_id,
            program_id=request.program_id,
            program_revision=request.program_revision,
            detector_id=request.detector.detector_id,
            target=request.target,
            attempt=str(request.execution_attempt),
        )
        if not self.store.create_action(action_id, request.campaign_id, request.program_id, key):
            raise ValueError("detector action already exists")
        self.store.transition_action(action_id, ActionState.UNPLANNED)
        self.store.transition_action(action_id, ActionState.PLANNED)
        self.store.transition_action(action_id, ActionState.AUTHORIZED)

    def authorization_persisted(
        self, request: DetectorExecutionRequest, action_id: str, permit_id: str
    ) -> None:
        self.store.transition_action(action_id, ActionState.PERMIT_ISSUED, permit_id=permit_id)
        self.store.increment(request.campaign_id, "permits_issued")

    def worker_starting(self, request: DetectorExecutionRequest, action_id: str) -> None:
        self.store.transition_action(action_id, ActionState.STARTING)
        self.store.transition_action(action_id, ActionState.EXECUTING)
        self.store.increment(request.campaign_id, "permits_consumed")
        self.store.increment(request.campaign_id, "network_actions")
        self.store.increment(request.campaign_id, "detector_runs_started")

    def result_persisted(
        self, request: DetectorExecutionRequest, result: DetectorRunResult
    ) -> None:
        if result.status is DetectorRunStatus.UNKNOWN_OUTCOME:
            self.store.transition_action(result.action_id, ActionState.UNKNOWN_OUTCOME)
        elif result.status is DetectorRunStatus.BLOCKED_BEFORE_IO:
            current = self.store.action_state(result.action_id)
            terminal = (
                ActionState.FAILED
                if current in {ActionState.STARTING, ActionState.EXECUTING}
                else ActionState.BLOCKED
            )
            self.store.transition_action(result.action_id, terminal)
            self.store.increment(request.campaign_id, "failed_before_io")
            self.store.increment(request.campaign_id, "permits_revoked")
            return
        elif result.status is DetectorRunStatus.FAILED:
            self.store.transition_action(result.action_id, ActionState.FAILED)
        else:
            evidence_id = (
                result.artifacts.evidence_ids[0] if result.artifacts.evidence_ids else None
            )
            self.store.transition_action(
                result.action_id, ActionState.EVIDENCE_RECORDED, evidence_id=evidence_id
            )
            self.store.transition_action(result.action_id, ActionState.VERIFIED)
            self.store.transition_action(result.action_id, ActionState.COMPLETED)
            if evidence_id:
                self.store.increment(request.campaign_id, "evidence")
            if result.finding_id:
                self.store.increment(request.campaign_id, "findings")
        self.store.reconcile_detector_run(
            request.campaign_id,
            {
                "requests_attempted": result.accounting.attempted,
                "requests_forwarded": result.accounting.forwarded,
                "responses_received": result.accounting.responses,
                "requests_blocked_before_io": result.accounting.blocked_before_io,
                "requests_failed_after_io": result.accounting.failed_after_io,
                "unknown_outcomes": result.accounting.unknown_outcomes,
            },
            authorized_budget=(
                result.authorization.payload.max_requests if result.authorization else 0
            ),
        )


def run_orchestrator_execution(
    config: AutonomousCampaignConfig,
    root: Path,
    *,
    requests: tuple[DetectorExecutionRequest, ...],
    adapters: tuple[TypedDetectorAdapter, ...],
    signing_key: str | bytes,
) -> tuple[dict, tuple[DetectorRunResult, ...]]:
    """Execute a precompiled typed batch through the production detector service."""
    if not config.execute or config.dry_run:
        raise ValueError("physical orchestrator execution requires execute mode")
    if not requests:
        raise ValueError("physical orchestrator execution requires typed detector requests")
    if any(request.campaign_id != config.campaign_id for request in requests):
        raise ValueError("detector request campaign binding mismatch")
    selected = set(config.selected_program_ids)
    if selected and any(request.program_id not in selected for request in requests):
        raise ValueError("detector request program is outside the selected campaign portfolio")
    start_orchestrator(config, root)
    store = OrchestratorStore(root / "campaign.db")
    service = DetectorExecutionService(
        root, signing_key, adapters, OrchestratorDetectorJournal(store)
    )
    results = tuple(service.execute(request) for request in requests)
    partial = any(
        result.status in {DetectorRunStatus.FAILED, DetectorRunStatus.UNKNOWN_OUTCOME}
        for result in results
    )
    finalize_orchestrator(
        store,
        config.campaign_id,
        root,
        partial=partial,
        readiness=CampaignReadiness.DEGRADED_COVERAGE,
    )
    return store.snapshot(config.campaign_id), results


def start_orchestrator(config: AutonomousCampaignConfig, root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    store = OrchestratorStore(root / "campaign.db")
    store.create_campaign(config)
    store.transition_campaign(config.campaign_id, CampaignState.PREFLIGHT, "configuration accepted")
    store.transition_campaign(
        config.campaign_id, CampaignState.READY, "durable storage initialized"
    )
    store.transition_campaign(config.campaign_id, CampaignState.RUNNING, "autonomous loop started")
    store.event(config.campaign_id, "campaign.started", {"platforms": list(config.platforms)})
    if config.dry_run:
        store.transition_campaign(
            config.campaign_id, CampaignState.COMPLETED, "dry-run logical pipeline completed"
        )
    store.checkpoint(config.campaign_id, "start completed")
    write_live_status(store, config.campaign_id, root)
    return store.snapshot(config.campaign_id)


def request_stop(store: OrchestratorStore, campaign_id: str, root: Path) -> None:
    state = store.campaign_state(campaign_id)
    if state is CampaignState.RUNNING:
        store.transition_campaign(
            campaign_id, CampaignState.PAUSING, "operator requested graceful stop"
        )
        store.checkpoint(campaign_id, "new work stopped; no in-flight action registered")
        store.transition_campaign(campaign_id, CampaignState.PAUSED, "safe drain completed")
    write_live_status(store, campaign_id, root)


def resume_orchestrator(store: OrchestratorStore, campaign_id: str, root: Path) -> None:
    snapshot = store.snapshot(campaign_id)
    uncertain = [row for row in snapshot["actions"] if row["state"] == "unknown_outcome"]
    if uncertain:
        store.event(campaign_id, "campaign.resume_blocked", {"unknown_outcomes": len(uncertain)})
        raise ValueError("unknown outcomes require recovery review and are never replayed blindly")
    store.transition_campaign(campaign_id, CampaignState.PREFLIGHT, "safe resume requested")
    store.transition_campaign(campaign_id, CampaignState.READY, "revalidation completed")
    store.transition_campaign(
        campaign_id, CampaignState.RUNNING, "fresh planning required; old permits not reused"
    )
    store.checkpoint(campaign_id, "resume completed")
    write_live_status(store, campaign_id, root)


def write_live_status(store: OrchestratorStore, campaign_id: str, root: Path) -> Path:
    snapshot = store.snapshot(campaign_id)
    path = root / "live-status.json"
    path.write_text(
        json.dumps(snapshot, sort_keys=True, indent=2, default=str) + "\n", encoding="utf-8"
    )
    return path


def finalize_orchestrator(
    store: OrchestratorStore,
    campaign_id: str,
    root: Path,
    *,
    partial: bool = False,
    readiness: CampaignReadiness = CampaignReadiness.FULL_UNATTENDED_READY,
) -> Path:
    state = store.campaign_state(campaign_id)
    if state is CampaignState.RUNNING:
        store.transition_campaign(
            campaign_id, CampaignState.DRAINING, "deadline/no-progress reached"
        )
    final = CampaignState.PARTIALLY_COMPLETED if partial else CampaignState.COMPLETED
    if store.campaign_state(campaign_id) is CampaignState.DRAINING:
        store.transition_campaign(campaign_id, final, "final reports consolidated")
    status = write_live_status(store, campaign_id, root)
    report = root / "campaign-report.md"
    snapshot = store.snapshot(campaign_id)
    counters = snapshot["counters"]
    report.write_text(
        f"# ASTP Autonomous Campaign — {campaign_id}\n\nReport state: {'partial' if partial else 'final'}\n\n## Status\n\n- Readiness: {readiness.value.upper()}\n- Coverage: {'DEGRADED' if readiness is CampaignReadiness.DEGRADED_COVERAGE else 'COMPLETE'}\n\n## Detector runs\n\n- Started: {counters['detector_runs_started']}\n- Completed: {counters['detector_runs_completed']}\n\n## Permit accounting\n\n- Issued: {counters['permits_issued']}\n- Consumed: {counters['permits_consumed']}\n- Expired: {counters['permits_expired']}\n- Revoked: {counters['permits_revoked']}\n\n## Request accounting\n\n- Attempted: {counters['requests_attempted']}\n- Forwarded: {counters['requests_forwarded']}\n- Responses: {counters['responses_received']}\n- Blocked before I/O: {counters['requests_blocked_before_io']}\n- Failed after I/O: {counters['requests_failed_after_io']}\n- Unknown outcome: {counters['unknown_outcomes']}\n- Evidence: {counters['evidence']}\n- Findings: {counters['findings']}\n",
        encoding="utf-8",
    )
    artifacts = {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "campaign-manifest.json"
        and path.suffix != ".db"
        and not path.name.endswith(("-wal", "-shm"))
    }
    artifacts.update({"live-status.json": status, "campaign-report.md": report})
    manifest = build_campaign_manifest(
        campaign_id,
        artifacts,
        report_state="partial" if partial else "final",
    )
    (root / "campaign-manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return report
