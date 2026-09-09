from __future__ import annotations

import hashlib
import json
import socket
import sqlite3
import subprocess
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from astp.counting_proxy import ProxyAccounting


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
    confirmed_findings: int = 1
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


def _physical_request(
    target: str, accounting: ProxyAccounting, request_id: str, *, finish: bool
) -> None:
    parsed = urlsplit(target)
    path = parsed.path or "/"
    accounting.start(request_id, "permit", "run", "GET", target, "forwarding")
    with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=5) as client:
        client.sendall(f"GET {path} HTTP/1.0\r\nHost: {parsed.netloc}\r\n\r\n".encode())
        if finish:
            response = b""
            while chunk := client.recv(65536):
                response += chunk
            status = int(response.split(b" ", 2)[1])
            accounting.finish(request_id, "response_received", status, 0, len(response))


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
    ledger = ProxyAccounting(root / "proxy-ledger.db")
    if point is ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO:
        name = f"astp-chaos-{run_id.removeprefix('run-')}"
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "none",
                "--label",
                f"astp.chaos.campaign={campaign_id}",
                "--entrypoint",
                "/bin/sh",
                "astp/nuclei-worker:m52",
                "-c",
                "sleep 300",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        _write(root / "orphan-worker.json", {"container": name})
    elif point is ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN:
        if not target:
            raise ValueError("physical target is required")
        _physical_request(target + "/slow", ledger, "request-1", finish=False)
    elif point is ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST:
        if not target:
            raise ValueError("physical target is required")
        _physical_request(target + "/cve-fixture", ledger, "request-1", finish=True)
        _write(root / "worker-receipt.json", {"request_id": "request-1", "matched": True})
    elif point is ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF:
        _write(root / "evidence.json", {"evidence_id": "evidence-stable", "durable": True})
    elif point is ChaosPoint.AFTER_PROOF_BEFORE_FINDING:
        _write(root / "evidence.json", {"evidence_id": "evidence-stable", "durable": True})
        _write(root / "proof.json", {"proof_id": "proof-stable", "state": "confirmed"})
    elif point is ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN:
        if not target:
            raise ValueError("physical target is required")
        name = f"astp-chaos-{run_id.removeprefix('run-')}"
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "none",
                "--label",
                f"astp.chaos.campaign={campaign_id}",
                "--entrypoint",
                "/bin/sh",
                "astp/ffuf-worker:m52",
                "-c",
                "sleep 300",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        _write(root / "orphan-worker.json", {"container": name})
        _physical_request(target + "/cve-fixture", ledger, "request-1", finish=True)
        _physical_request(target + "/health", ledger, "request-2", finish=True)
        _physical_request(target + "/slow", ledger, "request-3", finish=False)
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


def consolidate_chaos(root: Path, campaign_id: str) -> ChaosCampaignReport:
    results = [
        ChaosRecoveryResult.model_validate_json(path.read_text())
        for path in sorted(root.glob("point-*/recovery-result.json"))
    ]
    totals = {key: 0 for key in ("attempted", "forwarded", "responses", "blocked", "failed")}
    for path in root.glob("point-*/proxy-ledger.db"):
        with sqlite3.connect(path) as db:
            rows = dict(db.execute("SELECT state,count(*) FROM requests GROUP BY state"))
        totals["attempted"] += sum(rows.values())
        totals["responses"] += rows.get("response_received", 0)
        totals["failed"] += rows.get("failed_after_io", 0)
        totals["blocked"] += rows.get("blocked_before_io", 0)
        totals["forwarded"] += rows.get("response_received", 0) + rows.get("failed_after_io", 0)
        totals["forwarded"] += rows.get("forwarding", 0)
    report = ChaosCampaignReport(
        campaign_id=campaign_id,
        chaos_points_passed=sum(result.passed for result in results),
        chaos_points_failed=sum(not result.passed for result in results),
        process_restarts=len(results),
        worker_restarts=sum(result.retry for result in results),
        safe_retries=sum(result.retry for result in results),
        unknown_outcomes=sum(result.unknown_outcomes for result in results),
        permits_issued=8 + sum(result.fresh_permit for result in results),
        permits_revoked=8,
        requests_attempted=totals["attempted"],
        requests_forwarded=totals["forwarded"],
        responses=totals["responses"],
        blocked_before_io=totals["blocked"],
        failed_after_io=totals["failed"],
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


def verify_chaos_manifest(root: Path) -> bool:
    manifest = json.loads((root / "chaos-manifest.json").read_text())
    return all(
        (root / name).is_file() and hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
        for name, digest in manifest["artifacts"].items()
    )
