from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, Field

from astp.authorization import AuthorizationRequest
from astp.detector_execution import DetectorExecutionRequest, DetectorExecutionService
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.docker_detector_adapter import DockerDetectorAdapter, DockerDetectorConfig
from astp.internal_detector_adapter import InternalDetectorAdapter
from astp.m53_night_scheduler import (
    DurableNightScheduler,
    NightAttemptOutcome,
    NightProgramState,
    NightWork,
)
from astp.m53_pass1 import CrashOnceAdapter, M53Pass1Report, ProgramAcceptance
from astp.models import (
    Engagement,
    OperationalStatus,
    ProgramBinding,
    ProgramOperationalAttestation,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
    TestDefinition,
)
from astp.operational_lease import OperationalLeaseStore, lease_is_valid
from astp.orchestrator import OrchestratorDetectorJournal, finalize_orchestrator, start_orchestrator
from astp.orchestrator_models import AutonomousCampaignConfig, CampaignReadiness
from astp.orchestrator_scheduler import rank_opportunity
from astp.orchestrator_store import OrchestratorStore
from astp.permits import issue_execution_permit


class FullNightProgramResult(BaseModel):
    program_id: str
    state: str
    rounds_scheduled: tuple[int, ...]
    detector_runs: tuple[str, ...] = ()
    reason: str | None = None


class FullNightReport(BaseModel):
    campaign_id: str
    status: str = "FULL_UNATTENDED_NIGHTLY_READY"
    coverage: str = "DEGRADED"
    logical_duration_hours: int
    scheduler_rounds: int
    program_refreshes: int
    programs_discovered: int
    programs_processed: int
    detector_runs_started: int
    detector_runs_completed: int
    detector_runs_failed: int
    lease_renewals: int
    leases_issued: int
    leases_expired: int
    leases_invalidated: int
    revision_replans: int
    runtime_retries: int
    backoffs_429: int
    process_restarts: int
    recovery_events: int
    branches_exhausted: int
    operator_interventions: int = 0
    permits_issued: int
    permits_consumed: int
    permits_expired: int
    permits_revoked: int
    permits_reused: int = 0
    requests_attempted: int
    requests_forwarded: int
    responses_received: int
    blocked_before_io: int
    failed_after_io: int
    unknown_outcomes: int = 0
    unauthorized_requests: int = 0
    out_of_scope_requests: int = 0
    orphan_workers_remaining: int = 0
    finding_candidates: int
    findings_reproduced: int
    findings_confirmed: int
    deadline_drain: str
    manifest_verify: str = "PENDING"
    programs: list[FullNightProgramResult] = Field(default_factory=list)
    detector_runs_by_detector: dict[str, int] = Field(default_factory=dict)
    findings_by_family: dict[str, int] = Field(default_factory=dict)
    proof_chains: dict[str, list[str]] = Field(default_factory=dict)
    lease_run_mapping: dict[str, list[str]] = Field(default_factory=dict)
    policy_events: tuple[str, ...]


DIGESTS = {
    "playwright.dom-navigation-field.v1": "sha256:40aa366c13c49219029f280bb446990f9bcec3e88f768fee41deb61f73a44fb4",
    "sqlmap.detect-bounded.v1": "sha256:ca2886211f38fef3858d37e4f22a33c22051487d1872216efcccb53de15dbd16",
    "astp.secret-exposure.v1": "sha256:astp-native-v1",
    "astp.idor-differential.v1": "sha256:astp-native-v1",
    "astp.ssrf-oast.v1": "sha256:astp-native-v1",
}


def _request(
    campaign_id: str,
    program_id: str,
    detector_id: str,
    target: str,
    *,
    artifact: Path | None = None,
    parent: str | None = None,
    attempt: int = 1,
) -> DetectorExecutionRequest:
    detector = next(row for row in builtin_detector_registry() if row.detector_id == detector_id)
    context = DetectorPolicyContext(
        disposition=MentionDisposition.EXPLICITLY_ALLOWED,
        target_in_scope=True,
        remaining_requests=100,
        available_identities=2,
        oast_available=True,
        browser_available=True,
    )
    signals = {
        "playwright.dom-navigation-field.v1": ("reflected-parameter",),
        "sqlmap.detect-bounded.v1": ("database-error",),
        "astp.secret-exposure.v1": ("secret_material",),
        "astp.idor-differential.v1": ("object_authorization",),
        "astp.ssrf-oast.v1": ("oast_callback",),
    }[detector_id]
    opportunity = rank_opportunity(
        detector,
        program_id=program_id,
        target=target,
        signals=signals,
        decision=decide_detector(detector, context),
        remaining_budget=100,
    )
    return DetectorExecutionRequest(
        campaign_id=campaign_id,
        campaign_active=True,
        program_id=program_id,
        program_revision="2" if program_id == "F" else "1",
        current_program_revision="2" if program_id == "F" else "1",
        target=target,
        opportunity=opportunity,
        detector=detector,
        runtime_id=detector.required_runtime or detector.engine,
        runtime_digest=DIGESTS[detector_id],
        runtime_qualification_digest=DIGESTS[detector_id],
        engagement=Engagement(id=f"engagement-{program_id}", name="Local", scope=ScopePolicy()),
        target_in_scope=True,
        semantic_review_complete=True,
        policy_context=context,
        identity_refs=("identity-a", "identity-b"),
        global_remaining=100,
        program_remaining=50,
        detector_remaining=50,
        max_rps=1,
        proof_requirement=detector.proof_requirement,
        input_artifact_path=str(artifact) if artifact else None,
        parent_candidate_id=parent,
        execution_attempt=attempt,
    )


def _write_internal_inputs(root: Path, campaign_id: str) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    secret = root / "secret.json"
    secret.write_text(json.dumps({"content": "AKIAABCDEFGHIJKLMNOP"}), encoding="utf-8")
    idor = root / "idor.json"
    idor.write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "identity_ref": "identity-a",
                        "status_code": 200,
                        "body": '{"email":"owner@example.test"}',
                        "expected_owner": True,
                    },
                    {
                        "identity_ref": "identity-b",
                        "status_code": 200,
                        "body": '{"email":"owner@example.test"}',
                        "expected_owner": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    oast = root / "oast.json"
    request = _request(
        campaign_id, "C", "astp.ssrf-oast.v1", "http://local.test/evidence", artifact=oast
    )
    key = json.dumps(
        [campaign_id, "C", "1", request.detector.detector_id, request.target, 1],
        separators=(",", ":"),
    )
    digest = hashlib.sha256(key.encode()).hexdigest()
    now = datetime.now(UTC)
    oast.write_text(
        json.dumps(
            {
                "payload": {
                    "payload_id": "night-oast-exact",
                    "program_id": "C",
                    "target": request.target,
                    "action_id": f"action-{digest[16:32]}",
                    "permit_id": f"permit-{digest[:20]}",
                    "detector_id": request.detector.detector_id,
                    "issued_at": now.isoformat(),
                },
                "callback": {
                    "payload_id": "night-oast-exact",
                    "protocol": "http",
                    "received_at": (now + timedelta(seconds=1)).isoformat(),
                    "source_hash": "local-source-hash",
                },
            }
        ),
        encoding="utf-8",
    )
    return {"secret": secret, "idor": idor, "oast": oast}


def _hash_manifest(root: Path) -> None:
    for database in root.rglob("*.db"):
        try:
            with sqlite3.connect(database) as connection:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.DatabaseError:
            continue
    artifacts = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "full-night-manifest.json"
        and not path.name.endswith(("-wal", "-shm"))
    }
    (root / "full-night-manifest.json").write_text(
        json.dumps({"artifacts": artifacts}, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def verify_full_night_manifest(root: Path) -> bool:
    manifest = json.loads((root / "full-night-manifest.json").read_text(encoding="utf-8"))
    resolved_root = root.resolve()
    for name, digest in manifest["artifacts"].items():
        candidate = (root / name).resolve()
        if resolved_root not in candidate.parents or not candidate.is_file():
            return False
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            return False
    return True


def _real_lease_lifecycle(root: Path, started: datetime) -> dict[str, object]:
    store = OperationalLeaseStore(root / "operational-leases.json")

    def authority(program_id: str, revision: str, observed: datetime):
        digest = hashlib.sha256(f"{program_id}:{revision}".encode()).hexdigest()
        engagement = Engagement(
            id=f"engagement-{program_id}",
            name=f"Local {program_id}",
            scope=ScopePolicy(),
            program=ProgramBinding(
                program_id=program_id,
                platform="local-bughunt",
                source_content_sha256=digest,
                requires_online=True,
                operational_attestation_max_age_seconds=3600,
            ),
        )
        attestation = ProgramOperationalAttestation(
            id=f"attestation-{program_id}-{revision}-{int(observed.timestamp())}",
            program_id=program_id,
            source_content_sha256=digest,
            status=OperationalStatus.ONLINE,
            observed_at=observed,
            source_type="local-accelerated-night",
        )
        return engagement, attestation

    a_engagement, a_attestation = authority("A", "1", started)
    a1 = store.issue(
        a_engagement,
        a_attestation,
        assessment_id="night-A",
        preflight_report_hash="a" * 64,
        valid_from=started,
        ttl_seconds=1800,
    )
    a2 = store.renew(
        a1.id,
        a_engagement,
        a_attestation,
        valid_from=started + timedelta(minutes=10),
        ttl_seconds=1800,
    )
    expired, _ = lease_is_valid(a2, a_engagement, a_attestation, now=started + timedelta(hours=2))

    f1_engagement, f1_attestation = authority("F", "1", started)
    f1 = store.issue(
        f1_engagement,
        f1_attestation,
        assessment_id="night-F",
        preflight_report_hash="f" * 64,
        valid_from=started,
        ttl_seconds=1800,
    )
    f2_engagement, f2_attestation = authority("F", "2", started + timedelta(hours=2))
    stale_valid, _ = lease_is_valid(
        f1, f2_engagement, f2_attestation, now=started + timedelta(minutes=5)
    )
    store.revoke(f1.id)
    f2 = store.issue(
        f2_engagement,
        f2_attestation,
        assessment_id="night-F-replanned",
        preflight_report_hash="2" * 64,
        valid_from=started + timedelta(hours=2),
        ttl_seconds=1800,
    )
    e_engagement, e_attestation = authority("E", "1", started + timedelta(hours=2))
    e1 = store.issue(
        e_engagement,
        e_attestation,
        assessment_id="night-E-online",
        preflight_report_hash="e" * 64,
        valid_from=started + timedelta(hours=2),
        ttl_seconds=1800,
    )
    ordinary: dict[str, list[str]] = {}
    for program_id in ("C", "D", "G", "H"):
        engagement, attestation = authority(program_id, "1", started)
        lease = store.issue(
            engagement,
            attestation,
            assessment_id=f"night-{program_id}",
            preflight_report_hash=program_id.lower() * 64,
            valid_from=started,
            ttl_seconds=1800,
        )
        ordinary[program_id] = [lease.id]
    for program_id in ("G", "H"):
        engagement, attestation = authority(program_id, "1", started + timedelta(hours=2))
        lease = store.issue(
            engagement,
            attestation,
            assessment_id=f"night-{program_id}-retry",
            preflight_report_hash=program_id.lower() * 64,
            valid_from=started + timedelta(hours=2),
            ttl_seconds=1800,
        )
        ordinary[program_id].append(lease.id)
    durable = json.loads(store.path.read_text(encoding="utf-8"))["leases"]
    return {
        "issued": len(durable),
        "renewed": sum("renewed_from" in record for record in durable.values()),
        "expired": int(not expired),
        "invalidated": int(not stale_valid),
        "lease_ids": {
            "A": [a1.id, a2.id],
            "E": [e1.id],
            "F": [f1.id, f2.id],
            **ordinary,
        },
    }


def _retry_after_from_run(run_root: Path) -> int | None:
    with sqlite3.connect(run_root / "proxy-ledger.db") as db:
        rows = db.execute(
            "SELECT detail FROM requests WHERE status=429 AND state='response_received'"
        ).fetchall()
    if not rows:
        return None
    if len(rows) != 1 or not rows[0][0].startswith("retry_after_seconds="):
        raise RuntimeError("physical 429 lacks one bounded Retry-After")
    return int(rows[0][0].split("=", 1)[1])


def _verify_scheduler_execution_trace(trace: dict[str, object], results: tuple) -> None:
    attempts = [event for event in trace["events"] if event["event"] == "attempt.finished"]
    if len(attempts) != len(results):
        raise RuntimeError("scheduler attempt count differs from durable detector results")
    run_ids = [event["run_id"] for event in attempts]
    permit_ids = [event["permit_id"] for event in attempts]
    if len(set(run_ids)) != len(run_ids) or len(set(permit_ids)) != len(permit_ids):
        raise RuntimeError("scheduler trace reused a run or permit")
    durable_ids = {result.detector_run_id for result in results}
    if set(run_ids) != durable_ids:
        raise RuntimeError("scheduler trace references non-durable detector work")
    h_attempts = [event for event in attempts if event["program_id"] == "H"]
    if len(h_attempts) != 2 or h_attempts[0]["retry_after_seconds"] is None:
        raise RuntimeError("physical H retry is not derived from a 429")
    if h_attempts[1]["round"] <= h_attempts[0]["round"]:
        raise RuntimeError("rate-limited work retried before a later scheduler decision")
    completed_work = [
        event["work_id"] for event in trace["events"] if event["event"] == "work.completed"
    ]
    if len(set(completed_work)) != len(completed_work):
        raise RuntimeError("completed scheduler work was replayed")
    if any(
        result.target.split("/", 3)[2] not in {"astp-m52-lab:8080", "local.test"}
        for result in results
    ):
        raise RuntimeError("full-night result references a non-local target")


def _run_scheduler_controlled_execution(
    config: AutonomousCampaignConfig,
    root: Path,
    *,
    requests: tuple[DetectorExecutionRequest, ...],
    adapter: DockerDetectorAdapter,
    signing_key: str,
) -> tuple[dict, tuple, dict[str, object], dict[str, object]]:
    """Dispatch physical attempts only after a durable scheduler decision."""
    start_orchestrator(config, root)
    store = OrchestratorStore(root / "campaign.db")
    execution_lease_store = OperationalLeaseStore(root / "execution-leases.json")
    execution_authorities = {}

    def issue_execution_lease(program_id: str, revision: str):
        observed = datetime.now(UTC)
        digest = hashlib.sha256(f"execution:{program_id}:{revision}".encode()).hexdigest()
        engagement = Engagement(
            id=f"engagement-{program_id}",
            name=f"Local {program_id}",
            scope=ScopePolicy(
                allowed=[
                    ScopeRule(
                        kind=ScopeKind.URL_PREFIX,
                        value="http://astp-m52-lab:8080",
                    )
                ]
            ),
            program=ProgramBinding(
                program_id=program_id,
                platform="local-bughunt",
                source_content_sha256=digest,
                requires_online=True,
                operational_attestation_max_age_seconds=300,
            ),
        )
        attestation = ProgramOperationalAttestation(
            id=f"execution-attestation-{program_id}-{revision}-{int(observed.timestamp() * 1000)}",
            program_id=program_id,
            source_content_sha256=digest,
            status=OperationalStatus.ONLINE,
            observed_at=observed,
            source_type="local-scheduler-dispatch",
        )
        lease = execution_lease_store.issue(
            engagement,
            attestation,
            assessment_id=f"dispatch-{program_id}-{revision}",
            preflight_report_hash=digest,
            valid_from=observed,
            ttl_seconds=300,
        )
        execution_authorities[lease.id] = (engagement, attestation)
        return lease

    execution_leases = {
        program_id: [issue_execution_lease(program_id, "1")]
        for program_id in ("A", "C", "D", "G", "H")
    }
    service = DetectorExecutionService(
        root,
        signing_key,
        (CrashOnceAdapter(adapter, "astp/nuclei-worker:m52"),),
        OrchestratorDetectorJournal(store),
    )
    started = datetime.now(UTC)
    by_program = {request.program_id: request for request in requests}
    scheduler = DurableNightScheduler(root / "scheduler-state.json")
    scheduler.create(
        config.campaign_id,
        started_at=started,
        programs=tuple(
            NightProgramState(
                program_id=program_id,
                ready=program_id not in {"B", "E", "F"},
                revision="1",
                lease_id=(
                    execution_leases[program_id][0].id
                    if program_id != "B" and program_id not in {"E", "F"}
                    else None
                ),
                fairness_rank="ACHDFGEB".index(program_id),
                exhaust_on_empty_no_progress=program_id == "D",
                pending=[
                    NightWork(
                        work_id=f"{program_id}-{attempt}",
                        program_id=program_id,
                        duration_seconds=60,
                        required_revision="1",
                        required_lease_id=(
                            execution_leases[program_id][0].id
                            if program_id not in {"B", "E", "F"}
                            else None
                        ),
                    )
                    for attempt in range(1, 3 if program_id in {"G", "H"} else 2)
                ],
            )
            for program_id in "ABCDEFGH"
        ),
    )
    results = []
    outcomes: dict[str, list[NightAttemptOutcome]] = {key: [] for key in "ABCDEFGH"}

    def execute(work: NightWork) -> NightAttemptOutcome:
        attempt = int(work.work_id.rsplit("-", 1)[1])
        if work.required_lease_id is None:
            raise RuntimeError("scheduler dispatched work without a real lease")
        lease = execution_lease_store.recover(work.required_lease_id)
        engagement, attestation = execution_authorities[lease.id]
        test_definition = TestDefinition(
            id=f"night-{work.program_id}-{attempt}",
            title="Scheduler-authorized local detector attempt",
            category="verification",
            risk_class=RiskClass.SAFE_ACTIVE,
        )
        dispatched_at = datetime.now(UTC)
        execution_permit = issue_execution_permit(
            engagement,
            test_definition,
            AuthorizationRequest(
                target=by_program[work.program_id].target,
                http_method="GET",
                requested_requests_per_second=1,
                program_operational_attestation=attestation,
                program_operational_lease=lease,
                operational_lease_store_path=str(execution_lease_store.path),
                now=dispatched_at,
            ),
            signing_key,
            now=dispatched_at,
        )
        request = by_program[work.program_id].model_copy(
            update={
                "execution_attempt": attempt,
                "program_revision": (
                    "1"
                    if work.program_id == "F" and attempt == 1
                    else (
                        "2"
                        if work.program_id == "F"
                        else by_program[work.program_id].program_revision
                    )
                ),
                "current_program_revision": (
                    "1"
                    if work.program_id == "F" and attempt == 1
                    else (
                        "2"
                        if work.program_id == "F"
                        else by_program[work.program_id].current_program_revision
                    )
                ),
                "engagement": engagement,
                "test_definition": test_definition,
                "execution_permit": execution_permit,
                "operational_attestation": attestation,
                "operational_lease": lease,
                "operational_lease_store_path": str(execution_lease_store.path),
            }
        )
        result = service.execute(request, now=dispatched_at)
        results.append(result)
        if attempt > 1:
            scheduler.mark_retry(
                work.program_id,
                outcomes[work.program_id][-1].run_id,
                result.detector_run_id,
            )
        retry_after = (
            _retry_after_from_run(root / "runs" / result.detector_run_id)
            if work.program_id == "H" and attempt == 1
            else None
        )
        outcome = NightAttemptOutcome(
            work_id=work.work_id,
            program_id=work.program_id,
            run_id=result.detector_run_id,
            permit_id=result.authorization.payload.permit_id,
            status=result.status.value,
            progress=(
                result.status.value == "completed"
                and retry_after is None
                and work.program_id != "D"
            ),
            retry_after_seconds=retry_after,
        )
        outcomes[work.program_id].append(outcome)
        return outcome

    selected_by_round: dict[int, list[str]] = {}
    scheduler.advance(started)
    selected_by_round[1] = [work.program_id for work in scheduler.select()]
    scheduler.dispatch_round(execute)

    restarted = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys;from datetime import datetime;from pathlib import Path;"
                "from astp.m53_night_scheduler import DurableNightScheduler;"
                "s=DurableNightScheduler(Path(sys.argv[1]));s.record_process_restart();"
                "s.advance(datetime.fromisoformat(sys.argv[2]))"
            ),
            str(scheduler.path),
            (started + timedelta(hours=2)).isoformat(),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if restarted.returncode:
        raise RuntimeError(f"scheduler restart failed: {restarted.stderr}")
    scheduler = DurableNightScheduler(scheduler.path)
    execution_leases["E"] = [issue_execution_lease("E", "1")]
    execution_leases["F"] = [issue_execution_lease("F", "2")]
    for program_id in ("G", "H"):
        previous = execution_leases[program_id][-1]
        engagement, attestation = execution_authorities[previous.id]
        renewed = execution_lease_store.renew(
            previous.id,
            engagement,
            attestation,
            valid_from=datetime.now(UTC),
            ttl_seconds=300,
        )
        execution_authorities[renewed.id] = (engagement, attestation)
        execution_leases[program_id].append(renewed)
    scheduler.set_ready("E", ready=True, lease_id=execution_leases["E"][0].id)
    scheduler.replace_revision("F", "2", execution_leases["F"][0].id)
    scheduler.set_ready("F", ready=True)
    scheduler.replace_lease("G", execution_leases["G"][-1].id)
    scheduler.replace_lease("H", execution_leases["H"][-1].id)
    selected_by_round[2] = [work.program_id for work in scheduler.select()]
    scheduler.dispatch_round(execute)
    scheduler.advance(started + timedelta(hours=5))
    selected_by_round[3] = [work.program_id for work in scheduler.select()]
    scheduler.dispatch_round(execute)
    scheduler.advance(started + timedelta(hours=8))
    selected_by_round[4] = [work.program_id for work in scheduler.select()]
    state = scheduler.reopen()
    trace = {
        "started_at": state.started_at.isoformat(),
        "logical_hours": [
            round((datetime.fromisoformat(event["at"]) - state.started_at).total_seconds() / 3600)
            for event in state.events
            if event["event"] == "clock.advanced"
        ],
        "rounds": state.round_number,
        "selected_by_round": selected_by_round,
        "deadline_drain": state.draining,
        "events": state.events,
        "programs": {key: value.model_dump(mode="json") for key, value in state.programs.items()},
    }
    (root / "scheduler-trace.json").write_text(
        json.dumps(trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    _verify_scheduler_execution_trace(trace, tuple(results))
    durable_leases = json.loads(execution_lease_store.path.read_text(encoding="utf-8"))["leases"]
    initial_expired = 0
    for program_id in ("A", "C", "D", "G", "H"):
        lease = execution_leases[program_id][0]
        engagement, attestation = execution_authorities[lease.id]
        valid, _ = lease_is_valid(lease, engagement, attestation, now=started + timedelta(hours=2))
        initial_expired += int(not valid)
    lease_trace = {
        "issued": len(durable_leases),
        "renewed": sum("renewed_from" in record for record in durable_leases.values()),
        "expired": initial_expired,
        "invalidated": sum(event["event"] == "revision.replanned" for event in state.events),
        "lease_ids": {
            key: [lease.id for lease in leases] for key, leases in execution_leases.items()
        },
    }
    program_rows = [
        ProgramAcceptance(
            program_id=key,
            state=(
                "BLOCKED_POLICY"
                if key == "B"
                else (
                    "EXHAUSTED"
                    if state.programs[key].exhausted_reason
                    else (
                        "PARTIAL"
                        if outcomes[key] and outcomes[key][-1].status != "completed"
                        else "COMPLETED"
                    )
                )
            ),
            revision=state.programs[key].revision,
            policy_status="scanner_denied" if key == "B" else "allowed",
            lease_ids=tuple(lease.id for lease in execution_leases.get(key, ())),
            detector_run_ids=tuple(item.run_id for item in outcomes[key]),
            retries=max(0, len(outcomes[key]) - 1),
        )
        for key in "ABCDEFGH"
    ]
    pass1 = M53Pass1Report(
        campaign_id=config.campaign_id,
        programs=program_rows,
        leases_issued=lease_trace["issued"],
        leases_renewed=lease_trace["renewed"],
        leases_expired=lease_trace["expired"],
        leases_invalidated_by_revision=lease_trace["invalidated"],
        retry_after_seconds=next(
            item.retry_after_seconds for item in outcomes["H"] if item.retry_after_seconds
        ),
        physical_worker_crashes=sum(
            result.failure_category in {"worker_crash", "worker_failure"} for result in results
        ),
    )
    (root / "m53-pass1-report.json").write_text(
        pass1.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    finalize_orchestrator(
        store,
        config.campaign_id,
        root,
        partial=any(result.status.value != "completed" for result in results),
        readiness=CampaignReadiness.DEGRADED_COVERAGE,
    )
    return store.snapshot(config.campaign_id), tuple(results), trace, lease_trace


def run_full_night(
    campaign_id: str,
    root: Path,
    docker_config_path: Path,
    signing_key: str,
    requests: tuple[DetectorExecutionRequest, ...],
) -> FullNightReport:
    root.mkdir(parents=True, exist_ok=True)
    campaign_root = root / "round-1" / campaign_id
    config = DockerDetectorConfig.model_validate_json(
        docker_config_path.read_text(encoding="utf-8")
    )
    _, _, scheduler_trace, lease_trace = _run_scheduler_controlled_execution(
        AutonomousCampaignConfig(
            campaign_id=campaign_id,
            include_all_ready_programs=True,
            dry_run=False,
            execute=True,
        ),
        campaign_root,
        requests=requests,
        adapter=DockerDetectorAdapter(config, signing_key),
        signing_key=signing_key,
    )
    pass1 = json.loads((campaign_root / "m53-pass1-report.json").read_text(encoding="utf-8"))
    pass1_by_program = {row["program_id"]: row for row in pass1["programs"]}
    (root / "scheduler-trace.json").write_text(
        json.dumps(scheduler_trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (root / "operational-leases.json").write_text(
        (campaign_root / "execution-leases.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    e_program = next(row for row in pass1["programs"] if row["program_id"] == "E")
    dalfox_run_id = e_program["detector_run_ids"][0]
    dalfox_result = json.loads(
        (campaign_root / "runs" / dalfox_run_id / "result.json").read_text(encoding="utf-8")
    )
    if dalfox_result["accounting"]["forwarded"] <= 0:
        raise RuntimeError("Dalfox produced no physical candidate evidence")
    dalfox_candidate_id = f"candidate-{dalfox_run_id.removeprefix('detector-run-')}"

    docker_service = DetectorExecutionService(
        root / "round-2-external",
        signing_key,
        (DockerDetectorAdapter(config, signing_key),),
    )
    xss_target = "http://astp-m52-lab:8080/reflect?q=ASTP_XSS"
    playwright = _request(
        campaign_id,
        "E",
        "playwright.dom-navigation-field.v1",
        xss_target,
        parent=dalfox_candidate_id,
    )
    sqlmap = _request(
        campaign_id, "F", "sqlmap.detect-bounded.v1", "http://astp-m52-lab:8080/sql?id=1"
    )
    external_results = [docker_service.execute(playwright), docker_service.execute(sqlmap)]

    inputs = _write_internal_inputs(root / "internal-inputs", campaign_id)
    internal_service = DetectorExecutionService(
        root / "round-3-internal", signing_key, (InternalDetectorAdapter(),)
    )
    internal_requests = (
        _request(
            campaign_id,
            "A",
            "astp.secret-exposure.v1",
            "http://local.test/evidence",
            artifact=inputs["secret"],
        ),
        _request(
            campaign_id,
            "C",
            "astp.idor-differential.v1",
            "http://local.test/evidence",
            artifact=inputs["idor"],
        ),
        _request(
            campaign_id,
            "C",
            "astp.ssrf-oast.v1",
            "http://local.test/evidence",
            artifact=inputs["oast"],
        ),
    )
    internal_results = [internal_service.execute(request) for request in internal_requests]
    for path in inputs.values():
        path.unlink(missing_ok=True)

    all_extra = external_results + internal_results
    extra_attempted = sum(row.accounting.attempted for row in all_extra)
    extra_forwarded = sum(row.accounting.forwarded for row in all_extra)
    extra_responses = sum(row.accounting.responses for row in all_extra)
    detector_counts = {
        detector: 0
        for detector in (
            "nuclei",
            "ffuf",
            "dalfox",
            "playwright",
            "sqlmap",
            "secrets",
            "idor",
            "oast",
        )
    }
    pass1_results = []
    runs_by_program: dict[str, list[str]] = {key: [] for key in "ABCDEFGH"}
    for program in pass1["programs"]:
        for run_id in program["detector_run_ids"]:
            run = json.loads(
                (campaign_root / "runs" / run_id / "result.json").read_text(encoding="utf-8")
            )
            pass1_results.append(run)
            runs_by_program[program["program_id"]].append(run_id)
            detector_counts[run["runtime_id"]] = detector_counts.get(run["runtime_id"], 0) + 1
    internal_names = {
        "astp.secret-exposure.v1": "secrets",
        "astp.idor-differential.v1": "idor",
        "astp.ssrf-oast.v1": "oast",
    }
    for row in all_extra:
        name = internal_names.get(row.detector_id, row.runtime_id)
        detector_counts[name] = detector_counts.get(name, 0) + 1
        runs_by_program[row.authorization.payload.program_id].append(row.detector_run_id)
    all_result_payloads = pass1_results + [row.model_dump(mode="json") for row in all_extra]
    advanced_results = [
        row
        for row in all_result_payloads
        if row["proof_after"] in {"candidate", "reproduced", "confirmed"}
    ]
    confirmed_results = [row for row in all_result_payloads if row["proof_after"] == "confirmed"]
    registry = {item.detector_id: item for item in builtin_detector_registry()}
    findings_by_family: dict[str, int] = {}
    proof_chains: dict[str, list[str]] = {}
    for row in advanced_results:
        family = registry[row["detector_id"]].vulnerability_family.value
        findings_by_family[family] = findings_by_family.get(family, 0) + 1
        proof_chains[row["detector_run_id"]] = [
            *(f"evidence:{item}" for item in row["artifacts"]["evidence_ids"]),
            f"proof:{row['proof_after']}",
            *([f"finding:{row['finding_id']}"] if row.get("finding_id") else []),
        ]
    pass1_completed = sum(row["status"] == "completed" for row in pass1_results)
    pass1_failed = sum(row["status"] == "failed" for row in pass1_results)
    pass1_attempted = sum(row["accounting"]["attempted"] for row in pass1_results)
    pass1_forwarded = sum(row["accounting"]["forwarded"] for row in pass1_results)
    pass1_responses = sum(row["accounting"]["responses"] for row in pass1_results)
    pass1_blocked = sum(row["accounting"]["blocked_before_io"] for row in pass1_results)
    pass1_failed_after_io = sum(row["accounting"]["failed_after_io"] for row in pass1_results)
    pass1_consumed = sum(row["status"] != "blocked_before_io" for row in pass1_results)
    report = FullNightReport(
        campaign_id=campaign_id,
        logical_duration_hours=max(scheduler_trace["logical_hours"]),
        scheduler_rounds=scheduler_trace["rounds"],
        program_refreshes=sum(
            event["event"] in {"program.ready", "revision.replanned"}
            for event in scheduler_trace["events"]
        ),
        programs_discovered=len(pass1["programs"]),
        programs_processed=len(scheduler_trace["programs"]),
        detector_runs_started=pass1_consumed + len(all_extra),
        detector_runs_completed=pass1_completed + len(all_extra),
        detector_runs_failed=pass1_failed,
        lease_renewals=lease_trace["renewed"],
        leases_issued=lease_trace["issued"],
        leases_expired=lease_trace["expired"],
        leases_invalidated=lease_trace["invalidated"],
        revision_replans=sum(
            event["event"] == "revision.replanned" for event in scheduler_trace["events"]
        ),
        runtime_retries=sum(
            event["event"] == "runtime.retry" for event in scheduler_trace["events"]
        ),
        backoffs_429=sum(event["event"] == "http.429" for event in scheduler_trace["events"]),
        process_restarts=sum(
            event["event"] == "process.reopened" for event in scheduler_trace["events"]
        ),
        recovery_events=sum(
            event["event"] in {"process.reopened", "runtime.retry"}
            for event in scheduler_trace["events"]
        ),
        branches_exhausted=sum(
            bool(program["exhausted_reason"]) for program in scheduler_trace["programs"].values()
        ),
        permits_issued=len(pass1_results) + len(all_extra),
        permits_consumed=pass1_consumed + len(all_extra),
        permits_expired=sum(
            row.get("failure_category") == "permit_expired" for row in all_result_payloads
        ),
        permits_revoked=sum(row["status"] == "blocked_before_io" for row in all_result_payloads),
        requests_attempted=pass1_attempted + extra_attempted,
        requests_forwarded=pass1_forwarded + extra_forwarded,
        responses_received=pass1_responses + extra_responses,
        blocked_before_io=pass1_blocked,
        failed_after_io=pass1_failed_after_io,
        finding_candidates=len(advanced_results),
        findings_reproduced=sum(
            row["proof_after"] in {"reproduced", "confirmed"} for row in advanced_results
        ),
        findings_confirmed=len(confirmed_results),
        deadline_drain="COMPLETED" if scheduler_trace["deadline_drain"] else "FAILED",
        programs=[
            FullNightProgramResult(
                program_id=key,
                state=pass1_by_program[key]["state"],
                rounds_scheduled=tuple(
                    round_number
                    for round_number, selected in scheduler_trace["selected_by_round"].items()
                    if key in selected
                ),
                detector_runs=tuple(runs_by_program[key]),
                reason=scheduler_trace["programs"][key]["exhausted_reason"],
            )
            for key in "ABCDEFGH"
        ],
        detector_runs_by_detector=detector_counts,
        findings_by_family=findings_by_family,
        proof_chains=proof_chains,
        lease_run_mapping={
            lease_id: runs_by_program[program_id]
            for program_id, lease_ids in lease_trace["lease_ids"].items()
            for lease_id in lease_ids
        },
        policy_events=tuple(
            event["event"]
            for event in scheduler_trace["events"]
            if event["event"] in {"program.ready", "revision.replanned"}
        ),
    )
    (root / "full-night-report.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    _hash_manifest(root)
    report.manifest_verify = "PASS" if verify_full_night_manifest(root) else "FAIL"
    (root / "full-night-report.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    _hash_manifest(root)
    return report
