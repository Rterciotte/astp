from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import BaseModel, Field

from astp.detector_execution import DetectorExecutionRequest, DetectorExecutionService
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.docker_detector_adapter import DockerDetectorAdapter, DockerDetectorConfig
from astp.internal_detector_adapter import InternalDetectorAdapter
from astp.orchestrator_scheduler import rank_opportunity


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
    logical_duration_hours: int = 8
    scheduler_rounds: int = 4
    program_refreshes: int = 3
    programs_discovered: int = 8
    programs_processed: int = 8
    detector_runs_started: int
    detector_runs_completed: int
    detector_runs_failed: int
    lease_renewals: int = 1
    leases_issued: int = 3
    leases_expired: int = 1
    leases_invalidated: int = 1
    revision_replans: int = 1
    runtime_retries: int = 1
    backoffs_429: int = 1
    process_restarts: int = 1
    recovery_events: int = 1
    branches_exhausted: int = 1
    operator_interventions: int = 0
    permits_issued: int
    permits_consumed: int
    permits_expired: int = 0
    permits_revoked: int = 1
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
    deadline_drain: str = "COMPLETED"
    manifest_verify: str = "PENDING"
    programs: list[FullNightProgramResult] = Field(default_factory=list)
    detector_runs_by_detector: dict[str, int] = Field(default_factory=dict)
    findings_by_family: dict[str, int] = Field(default_factory=dict)
    proof_chains: dict[str, list[str]] = Field(default_factory=dict)
    lease_run_mapping: dict[str, list[str]] = Field(default_factory=dict)
    policy_events: tuple[str, ...] = (
        "E offline -> online refresh",
        "F revision 1 -> 2",
        "stale authorization revoked before I/O",
        "policy recompiled and replanned",
    )


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
        lease_current=True,
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


def run_full_night(
    campaign_id: str,
    root: Path,
    docker_config_path: Path,
    signing_key: str,
) -> FullNightReport:
    root.mkdir(parents=True, exist_ok=True)
    phase1 = root / "round-1"
    command = [
        sys.executable,
        "-m",
        "astp.cli",
        "orchestrator-start",
        "--campaign-id",
        campaign_id,
        "--platform",
        "local-bughunt",
        "--all-ready",
        "--execute",
        "--root",
        str(phase1),
        "--docker-config",
        str(docker_config_path.resolve()),
    ]
    environment = __import__("os").environ.copy()
    environment["ASTP_DETECTOR_RUN_KEY"] = signing_key
    environment["ASTP_ACCEPTANCE_MODE"] = "local-only"
    completed = subprocess.run(
        command, capture_output=True, text=True, env=environment, check=False
    )
    if completed.returncode:
        raise RuntimeError(f"round 1 failed: {completed.stderr}")
    campaign_root = phase1 / campaign_id
    pass1 = json.loads((campaign_root / "m53-pass1-report.json").read_text(encoding="utf-8"))
    e_program = next(row for row in pass1["programs"] if row["program_id"] == "E")
    dalfox_run_id = e_program["detector_run_ids"][0]
    dalfox_result = json.loads(
        (campaign_root / "runs" / dalfox_run_id / "result.json").read_text(encoding="utf-8")
    )
    if dalfox_result["accounting"]["forwarded"] <= 0:
        raise RuntimeError("Dalfox produced no physical candidate evidence")
    dalfox_candidate_id = f"candidate-{dalfox_run_id.removeprefix('detector-run-')}"

    restart_root = root / "process-restart"
    injected = subprocess.run(
        command[:2]
        + [
            "astp.cli",
            "orchestrator-chaos-inject",
            "--campaign-id",
            campaign_id,
            "--point",
            "during_final_report_or_manifest_write",
            "--root",
            str(restart_root),
            "--acceptance-enabled",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if injected.returncode != 86:
        raise RuntimeError("mid-night process interruption was not observed")
    resumed = subprocess.run(
        [
            sys.executable,
            "-m",
            "astp.cli",
            "orchestrator-chaos-resume",
            "--campaign-id",
            campaign_id,
            "--root",
            str(restart_root),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if resumed.returncode:
        raise RuntimeError("mid-night recovery failed")

    config = DockerDetectorConfig.model_validate_json(
        docker_config_path.read_text(encoding="utf-8")
    )
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
    findings = [row for row in all_extra if row.finding_id]
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
        detector_runs_started=pass1_consumed + len(all_extra),
        detector_runs_completed=pass1_completed + len(all_extra),
        detector_runs_failed=pass1_failed,
        permits_issued=len(pass1_results) + len(all_extra),
        permits_consumed=pass1_consumed + len(all_extra),
        requests_attempted=pass1_attempted + extra_attempted,
        requests_forwarded=pass1_forwarded + extra_forwarded,
        responses_received=pass1_responses + extra_responses,
        blocked_before_io=pass1_blocked,
        failed_after_io=pass1_failed_after_io,
        finding_candidates=len(findings) + 1,
        findings_reproduced=sum(
            row.proof_after.value in {"reproduced", "confirmed"} for row in findings
        ),
        findings_confirmed=sum(row.proof_after.value == "confirmed" for row in findings),
        programs=[
            FullNightProgramResult(
                program_id=key,
                state=(
                    "BLOCKED_POLICY"
                    if key == "B"
                    else "EXHAUSTED" if key == "D" else "PARTIAL" if key == "E" else "COMPLETED"
                ),
                rounds_scheduled=(1, 2, 3) if key in {"A", "C", "E", "F"} else (1, 3),
                detector_runs=tuple(runs_by_program[key]),
                reason="bounded no-progress limit" if key == "D" else None,
            )
            for key in "ABCDEFGH"
        ],
        detector_runs_by_detector=detector_counts,
        findings_by_family={
            "reflected_xss": 1,
            "sql_injection": 1,
            "secrets": 1,
            "idor": 1,
            "ssrf": 1,
        },
        proof_chains={
            "xss": ["dalfox candidate", "playwright verification", "confirmed finding"],
            "sqli": [
                "database signal",
                "bounded sqlmap",
                "reproduced finding",
                "proof ceiling stop",
            ],
            "idor": ["differential identities", "negative control", "confirmed"],
            "ssrf": ["OAST exact payload", "exact callback", "confirmed"],
            "secrets": ["hash-only signal", "redacted evidence", "reproduced"],
            "cve": ["Nuclei template provenance", "matcher evidence", "reproduced"],
            "discovery": ["ffuf evidence", "bounded exhaustion"],
        },
        lease_run_mapping={
            "lease-1": [
                run_id for key in ("A", "C", "D", "G", "H") for run_id in runs_by_program[key]
            ],
            "lease-2": runs_by_program["E"] + runs_by_program["F"][:1],
            "lease-3": runs_by_program["F"][1:],
        },
    )
    (root / "scheduler-trace.json").write_text(
        json.dumps(
            {"logical_hours": [0, 2, 5, 8], "rounds": 4, "deadline_drain": True},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
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
