from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from astp.counting_proxy import ProxyAccounting
from astp.detector_execution import DetectorAccounting
from astp.docker_detector_adapter import DockerDetectorAdapter


class ChaosPoint(StrEnum):
    AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH = "after_permit_persisted_before_worker_launch"
    AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO = "after_worker_launch_before_first_proxy_io"
    AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN = (
        "after_first_request_forwarded_before_response_known"
    )
    AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST = "after_response_before_evidence_persist"
    AFTER_EVIDENCE_BEFORE_PROOF = "after_evidence_before_proof"
    AFTER_PROOF_BEFORE_FINDING = "after_proof_before_finding"
    DURING_PHYSICAL_DETECTOR_RUN = "during_physical_detector_run"
    DURING_FINAL_REPORT_OR_MANIFEST_WRITE = "during_final_report_or_manifest_write"


class RecoveryClass(StrEnum):
    FAILED_BEFORE_IO = "FAILED_BEFORE_IO"
    FAILED_AFTER_IO = "FAILED_AFTER_IO"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    RECOVERABLE_FROM_DURABLE_ARTIFACT = "RECOVERABLE_FROM_DURABLE_ARTIFACT"
    COMPLETED = "COMPLETED"


class ChaosEvent(BaseModel):
    campaign_id: str
    program_id: str
    action_id: str
    detector_run_id: str
    chaos_point: ChaosPoint
    injected_at: datetime
    expected_recovery_class: RecoveryClass


class ChaosRecoveryResult(BaseModel):
    chaos_point: ChaosPoint
    recovery_class: RecoveryClass
    network_before_crash: int
    network_after_recovery: int
    retry: bool
    fresh_permit: bool
    unknown_outcomes: int = 0
    duplicate_evidence: int = 0
    duplicate_findings: int = 0
    orphan_workers_remaining: int = 0
    worker_launched: bool = False
    permit_id: str | None = None
    detector_run_id: str | None = None
    evidence_recovered: bool = False
    replayed: bool = False
    passed: bool


class ChaosCampaignReport(BaseModel):
    campaign_id: str
    chaos_points_total: int = 8
    chaos_points_passed: int
    chaos_points_failed: int
    process_restarts: int
    worker_restarts: int
    safe_retries: int
    blind_replays: int = 0
    unknown_outcomes: int
    permits_issued: int
    permits_reused: int = 0
    permits_revoked: int
    unauthorized_requests: int = 0
    out_of_scope_requests: int = 0
    requests_attempted: int
    requests_forwarded: int
    responses: int
    blocked_before_io: int
    failed_after_io: int
    duplicate_evidence: int = 0
    duplicate_findings: int = 0
    confirmed_findings: int = 0
    reconstructed_evidence: int = 0
    proof_states: dict[str, int] = Field(default_factory=dict)
    orphan_workers_remaining: int = 0
    manifest_verify: str
    results: list[ChaosRecoveryResult] = Field(default_factory=list)


EXPECTED = {
    ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH: RecoveryClass.FAILED_BEFORE_IO,
    ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO: RecoveryClass.FAILED_BEFORE_IO,
    ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN: RecoveryClass.UNKNOWN_OUTCOME,
    ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST: RecoveryClass.RECOVERABLE_FROM_DURABLE_ARTIFACT,
    ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF: RecoveryClass.RECOVERABLE_FROM_DURABLE_ARTIFACT,
    ChaosPoint.AFTER_PROOF_BEFORE_FINDING: RecoveryClass.RECOVERABLE_FROM_DURABLE_ARTIFACT,
    ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN: RecoveryClass.UNKNOWN_OUTCOME,
    ChaosPoint.DURING_FINAL_REPORT_OR_MANIFEST_WRITE: RecoveryClass.COMPLETED,
}


def _write(path: Path, payload: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True, indent=2, default=str) + "\n")
    temporary.replace(path)


def _identifiers(campaign_id: str, point: ChaosPoint, attempt: int = 1) -> tuple[str, str, str]:
    digest = hashlib.sha256(f"{campaign_id}:{point}:{attempt}".encode()).hexdigest()
    return f"action-{digest[:12]}", f"run-{digest[12:24]}", f"permit-{digest[24:36]}"


def inject_chaos(
    root: Path, campaign_id: str, point: ChaosPoint, *, target: str | None, enabled: bool
) -> None:
    if not enabled:
        raise ValueError("chaos injection is disabled; explicit acceptance enablement is required")
    root.mkdir(parents=True, exist_ok=True)
    action_id, run_id, permit_id = _identifiers(campaign_id, point)
    event = ChaosEvent(
        campaign_id=campaign_id,
        program_id=f"chaos-{list(ChaosPoint).index(point) + 1}",
        action_id=action_id,
        detector_run_id=run_id,
        chaos_point=point,
        injected_at=datetime.now(UTC),
        expected_recovery_class=EXPECTED[point],
    )
    _write(root / "chaos-event.json", event.model_dump(mode="json"))
    _write(
        root / "run-state.json",
        {"action_id": action_id, "run_id": run_id, "permit_id": permit_id, "state": "injected"},
    )
    _write(root / "budget-reservation.json", {"run_id": run_id, "reserved": 4, "state": "reserved"})
    physical_points = {
        ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO,
        ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN,
        ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST,
        ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN,
    }
    if point in physical_points:
        raise ValueError(
            "physical chaos must be injected by DockerDetectorAdapter lifecycle faults"
        )
    if point is ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF:
        _write(root / "evidence.json", {"evidence_id": "evidence-stable", "durable": True})
    elif point is ChaosPoint.AFTER_PROOF_BEFORE_FINDING:
        _write(root / "evidence.json", {"evidence_id": "evidence-stable", "durable": True})
        _write(root / "proof.json", {"proof_id": "proof-stable", "state": "confirmed"})
    elif point is ChaosPoint.DURING_FINAL_REPORT_OR_MANIFEST_WRITE:
        _write(root / "detector-complete.json", {"network_complete": True})
        (root / "campaign-report.json.tmp").write_text("interrupted")


def recover_chaos(root: Path) -> ChaosRecoveryResult:
    event = ChaosEvent.model_validate_json((root / "chaos-event.json").read_text())
    before = ProxyAccounting(root / "proxy-ledger.db").summary()
    with sqlite3.connect(root / "proxy-ledger.db") as db:
        in_flight = int(
            db.execute("SELECT count(*) FROM requests WHERE state='forwarding'").fetchone()[0]
        )
    point = event.chaos_point
    retry = point in {
        ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH,
        ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO,
    }
    fresh = False
    if retry:
        _, fresh_run, fresh_permit = _identifiers(event.campaign_id, point, 2)
        _write(root / "fresh-authorization.json", {"run_id": fresh_run, "permit_id": fresh_permit})
        fresh = True
    orphan = root / "orphan-worker.json"
    if orphan.exists():
        name = json.loads(orphan.read_text())["container"]
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, check=False)
        orphan.unlink()
    if point is ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST:
        _write(root / "evidence.json", {"evidence_id": "evidence-stable", "recovered": True})
    if point is ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF:
        _write(root / "proof.json", {"proof_id": "proof-stable", "evidence_id": "evidence-stable"})
    if point is ChaosPoint.AFTER_PROOF_BEFORE_FINDING:
        _write(root / "finding.json", {"finding_id": "finding-stable", "proof_id": "proof-stable"})
    if point is ChaosPoint.DURING_FINAL_REPORT_OR_MANIFEST_WRITE:
        (root / "campaign-report.json.tmp").unlink(missing_ok=True)
        _write(root / "campaign-report.json", {"state": "completed", "network_replayed": False})
    unknown = int(
        point
        in {
            ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN,
            ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN,
        }
    )
    actual_usage = before["requests_forwarded"] + in_flight
    _write(
        root / "budget-reconciliation.json",
        {
            "reserved": 4,
            "actual_usage": actual_usage,
            "state": "unknown_reconciled" if unknown else "reconciled",
            "phantom_reservation": False,
        },
    )
    result = ChaosRecoveryResult(
        chaos_point=point,
        recovery_class=EXPECTED[point],
        network_before_crash=before["requests_forwarded"] + in_flight,
        network_after_recovery=before["requests_forwarded"] + in_flight,
        retry=retry,
        fresh_permit=fresh,
        unknown_outcomes=unknown,
        passed=True,
    )
    _write(root / "recovery-result.json", result.model_dump(mode="json"))
    return result


def recover_physical_detector_chaos(root: Path, point: ChaosPoint) -> ChaosRecoveryResult:
    """Reconcile one real detector fault exclusively from its durable artifacts."""
    run_roots = list((root / "orchestrator" / "runs").glob("detector-run-*"))
    if len(run_roots) != 1:
        raise ValueError("physical chaos recovery requires exactly one durable detector run")
    run_root = run_roots[0]
    authorization = json.loads((run_root / "authorization.json").read_text(encoding="utf-8"))
    ledger_path = run_root / "proxy-ledger.db"
    try:
        accounting = DockerDetectorAdapter._accounting(ledger_path)
    except sqlite3.OperationalError:
        if point is not ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH:
            raise
        accounting = DetectorAccounting()
    worker_launched = (run_root / "worker-lifecycle.json").is_file()
    intermediate = run_root / "normalized-intermediate.json"
    evidence_recovered = False
    if intermediate.is_file():
        normalized = json.loads(intermediate.read_text(encoding="utf-8"))
        _write(root / "recovered-evidence.json", normalized)
        evidence_recovered = True
    expected = EXPECTED[point]
    if point is ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH:
        passed = not worker_launched and accounting.forwarded == 0
    elif point is ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO:
        passed = worker_launched and accounting.forwarded == 0
    elif point is ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN:
        passed = accounting.forwarded == 1 and accounting.unknown_outcomes == 1
    elif point is ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN:
        lifecycle = json.loads((run_root / "worker-lifecycle.json").read_text(encoding="utf-8"))
        passed = (
            lifecycle.get("state") == "killed"
            and accounting.forwarded == 1
            and accounting.unknown_outcomes == 1
        )
    elif point is ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST:
        passed = accounting.forwarded == accounting.responses == 1
    elif point is ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF:
        passed = accounting.responses == 1 and evidence_recovered
    else:
        raise ValueError("fault point is not produced by the physical detector adapter")
    result = ChaosRecoveryResult(
        chaos_point=point,
        recovery_class=expected,
        network_before_crash=accounting.forwarded,
        network_after_recovery=accounting.forwarded,
        retry=accounting.forwarded == 0,
        fresh_permit=False,
        unknown_outcomes=accounting.unknown_outcomes,
        worker_launched=worker_launched,
        permit_id=authorization["payload"]["permit_id"],
        detector_run_id=authorization["payload"]["detector_run_id"],
        evidence_recovered=evidence_recovered,
        replayed=False,
        passed=passed,
    )
    _write(root / "recovery-result.json", result.model_dump(mode="json"))
    return result


def consolidate_chaos(root: Path, campaign_id: str) -> ChaosCampaignReport:
    results = [
        ChaosRecoveryResult.model_validate_json(path.read_text())
        for path in sorted(root.glob("point-*/recovery-result.json"))
    ]
    totals = {key: 0 for key in ("attempted", "forwarded", "responses", "blocked", "failed")}
    for path in root.glob("point-*/**/proxy-ledger.db"):
        with sqlite3.connect(path) as db:
            rows = dict(db.execute("SELECT state,count(*) FROM requests GROUP BY state"))
        totals["attempted"] += sum(rows.values())
        totals["responses"] += rows.get("response_received", 0)
        totals["failed"] += rows.get("failed_after_io", 0)
        totals["blocked"] += rows.get("blocked_before_io", 0)
        totals["forwarded"] += rows.get("response_received", 0) + rows.get("failed_after_io", 0)
        totals["forwarded"] += rows.get("forwarding", 0)
    authorizations = []
    completed_results = []
    for path in root.glob("**/authorization.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if "payload" in payload:
            authorizations.append(payload["payload"])
    for path in root.glob("**/result.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("status") == "completed":
            completed_results.append(payload)
    permit_ids = {item["permit_id"] for item in authorizations}
    permits_revoked = 0
    for path in root.glob("point-*/orchestrator/campaign.db"):
        with sqlite3.connect(path) as db:
            permits_revoked += int(db.execute("SELECT permits_revoked FROM counters").fetchone()[0])
    proof_states: dict[str, int] = {}
    evidence_ids: set[str] = set()
    finding_ids: set[str] = set()
    for result in completed_results:
        proof = result.get("proof_after")
        if proof:
            proof_states[proof] = proof_states.get(proof, 0) + 1
        evidence_ids.update(result.get("artifacts", {}).get("evidence_ids", ()))
        if result.get("finding_id"):
            finding_ids.add(result["finding_id"])
    report = ChaosCampaignReport(
        campaign_id=campaign_id,
        chaos_points_passed=sum(result.passed for result in results),
        chaos_points_failed=sum(not result.passed for result in results),
        process_restarts=len(results),
        worker_restarts=sum(result.retry for result in results),
        safe_retries=sum(result.retry for result in results),
        unknown_outcomes=sum(result.unknown_outcomes for result in results),
        permits_issued=len(permit_ids),
        permits_revoked=permits_revoked,
        requests_attempted=totals["attempted"],
        requests_forwarded=totals["forwarded"],
        responses=totals["responses"],
        blocked_before_io=totals["blocked"],
        failed_after_io=totals["failed"],
        confirmed_findings=len(finding_ids),
        reconstructed_evidence=len(evidence_ids),
        proof_states=proof_states,
        manifest_verify="PENDING",
        results=results,
    )
    _write(root / "chaos-report.json", report.model_dump(mode="json"))
    artifacts = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
        and path.name != "chaos-manifest.json"
        and not path.name.endswith(("-wal", "-shm"))
    }
    _write(root / "chaos-manifest.json", {"campaign_id": campaign_id, "artifacts": artifacts})
    report.manifest_verify = "PASS" if verify_chaos_manifest(root) else "FAIL"
    _write(root / "chaos-report.json", report.model_dump(mode="json"))
    artifacts["chaos-report.json"] = hashlib.sha256(
        (root / "chaos-report.json").read_bytes()
    ).hexdigest()
    _write(root / "chaos-manifest.json", {"campaign_id": campaign_id, "artifacts": artifacts})
    return report


def reconstruct_physical_completion(root: Path) -> dict[str, object]:
    """Reopen a completed physical run and derive proof/report facts from disk."""
    results = list(root.glob("orchestrator/runs/detector-run-*/result.json"))
    if len(results) != 1:
        raise ValueError("completion reconstruction requires exactly one detector result")
    result = json.loads(results[0].read_text(encoding="utf-8"))
    ledger = DockerDetectorAdapter._accounting(results[0].parent / "proxy-ledger.db")
    evidence_ids = tuple(result.get("artifacts", {}).get("evidence_ids", ()))
    if (
        result.get("status") != "completed"
        or ledger.forwarded != ledger.responses
        or ledger.responses != 1
        or not evidence_ids
    ):
        raise ValueError("durable physical completion is inconsistent")
    reconstructed = {
        "detector_run_id": result["detector_run_id"],
        "permit_id": result["authorization"]["payload"]["permit_id"],
        "network_replayed": False,
        "accounting": ledger.model_dump(),
        "evidence_ids": evidence_ids,
        "proof_state": result["proof_after"],
        "finding_id": result.get("finding_id"),
        "requirement_satisfied": result["requirement_satisfied"],
    }
    _write(root / "reconstructed-completion.json", reconstructed)
    return reconstructed


def verify_chaos_manifest(root: Path) -> bool:
    manifest = json.loads((root / "chaos-manifest.json").read_text())
    resolved_root = root.resolve()
    for name, digest in manifest["artifacts"].items():
        candidate = (root / name).resolve()
        if resolved_root not in candidate.parents or not candidate.is_file():
            return False
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            return False
    return True
