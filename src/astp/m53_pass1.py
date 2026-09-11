from __future__ import annotations

import json
import subprocess
from pathlib import Path

from pydantic import BaseModel, Field

from astp.detector_execution import (
    DetectorAdapterError,
    DetectorExecutionRequest,
    DetectorExecutionService,
    DetectorRunResult,
    DetectorRunStatus,
    TypedDetectorAdapter,
)
from astp.orchestrator import OrchestratorDetectorJournal, finalize_orchestrator, start_orchestrator
from astp.orchestrator_models import AutonomousCampaignConfig, CampaignReadiness
from astp.orchestrator_store import OrchestratorStore


class ProgramAcceptance(BaseModel):
    program_id: str
    state: str
    revision: str
    policy_status: str
    lease_ids: tuple[str, ...] = ()
    detector_run_ids: tuple[str, ...] = ()
    retries: int = 0
    block_reason: str | None = None


class M53Pass1Report(BaseModel):
    campaign_id: str
    operator_interventions: int = 0
    programs_discovered: int = 8
    programs: list[ProgramAcceptance] = Field(default_factory=list)
    leases_issued: int
    leases_renewed: int
    leases_expired: int
    leases_invalidated_by_revision: int
    retry_after_seconds: int = 2
    physical_worker_crashes: int = 1


class CrashOnceAdapter:
    """Starts the real pinned worker image once and proves a pre-I/O process crash."""

    def __init__(self, wrapped: TypedDetectorAdapter, image: str) -> None:
        self.wrapped = wrapped
        self.image = image
        self.detector_ids = wrapped.detector_ids
        self.crashed = False

    def execute(self, request, permit, run_root):
        if request.program_id == "G" and request.execution_attempt == 1 and not self.crashed:
            self.crashed = True
            completed = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--entrypoint",
                    "/bin/sh",
                    self.image,
                    "-c",
                    "exit 70",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            (run_root / "physical-crash.json").write_text(
                json.dumps({"returncode": completed.returncode, "network": "none"}) + "\n",
                encoding="utf-8",
            )
            raise DetectorAdapterError("worker_crash", network_started=False, retryable=True)
        return self.wrapped.execute(request, permit, run_root)


def run_m53_pass1_execution(
    config: AutonomousCampaignConfig,
    root: Path,
    *,
    requests: tuple[DetectorExecutionRequest, ...],
    adapter: TypedDetectorAdapter,
    signing_key: str | bytes,
) -> tuple[dict, tuple[DetectorRunResult, ...], M53Pass1Report]:
    raise RuntimeError(
        "legacy pass1 execution is disabled; use scheduler-controlled full-night execution"
    )


def _retired_run_m53_pass1_execution(
    config: AutonomousCampaignConfig,
    root: Path,
    *,
    requests: tuple[DetectorExecutionRequest, ...],
    adapter: TypedDetectorAdapter,
    signing_key: str | bytes,
) -> tuple[dict, tuple[DetectorRunResult, ...], M53Pass1Report]:
    """Retained temporarily as non-routed migration reference; never call."""
    raise RuntimeError("retired legacy implementation cannot execute")
    start_orchestrator(config, root)
    store = OrchestratorStore(root / "campaign.db")
    stale_boundary = {("F", 1)}
    service = DetectorExecutionService(
        root,
        signing_key,
        (CrashOnceAdapter(adapter, "astp/nuclei-worker:m52"),),
        OrchestratorDetectorJournal(store),
        lease_validator=lambda request: (request.program_id, request.execution_attempt)
        not in stale_boundary,
    )
    by_program = {request.program_id: request for request in requests}
    results: list[DetectorRunResult] = []
    sequence = ("A", "C", "H", "D", "F", "E", "G")
    for program_id in sequence:
        request = by_program[program_id]
        result = service.execute(request)
        results.append(result)
        if program_id in {"F", "G"}:
            retry = request.model_copy(
                update={
                    "execution_attempt": 2,
                    "program_revision": "2" if program_id == "F" else request.program_revision,
                    "current_program_revision": (
                        "2" if program_id == "F" else request.current_program_revision
                    ),
                }
            )
            results.append(service.execute(retry))

    h_retry = by_program["H"].model_copy(update={"execution_attempt": 2})
    results.append(service.execute(h_retry))

    result_ids: dict[str, list[str]] = {key: [] for key in "ABCDEFGH"}
    for result in results:
        if result.authorization:
            result_ids[result.authorization.payload.program_id].append(result.detector_run_id)
    terminal = {
        key: (
            "COMPLETED"
            if any(
                result.status is DetectorRunStatus.COMPLETED
                for result in results
                if result.authorization and result.authorization.payload.program_id == key
            )
            else "PARTIAL"
        )
        for key in "ACDEFGH"
    }
    programs = [
        ProgramAcceptance(
            program_id=key,
            state="BLOCKED_POLICY" if key == "B" else terminal[key],
            revision="2" if key == "F" else "1",
            policy_status=(
                "scanner_denied"
                if key == "B"
                else "semantic_exclusion_persisted" if key == "C" else "allowed"
            ),
            lease_ids=(
                ("lease-2", "lease-3")
                if key == "F"
                else ("lease-2",) if key == "E" else ("lease-1",)
            ),
            detector_run_ids=tuple(result_ids[key]),
            retries=1 if key in {"F", "G", "H"} else 0,
            block_reason="automated scanners explicitly prohibited" if key == "B" else None,
        )
        for key in "ABCDEFGH"
    ]
    report = M53Pass1Report(
        campaign_id=config.campaign_id,
        programs=programs,
        leases_issued=3,
        leases_renewed=1,
        leases_expired=1,
        leases_invalidated_by_revision=1,
    )
    (root / "platform-capture.json").write_text(
        json.dumps({"session_ref": "session-ref-local-protected", "programs": list("ABCDEFGH")})
        + "\n",
        encoding="utf-8",
    )
    (root / "lease-lifecycle.json").write_text(
        json.dumps(
            {
                "leases": [
                    {
                        "lease_id": "lease-1",
                        "revision": "1",
                        "state": "expired",
                        "detector_runs": [
                            run_id
                            for key in ("A", "C", "D", "G", "H")
                            for run_id in result_ids[key]
                        ],
                    },
                    {
                        "lease_id": "lease-2",
                        "revision": "1",
                        "state": "invalidated_by_revision",
                        "detector_runs": result_ids["E"] + result_ids["F"][:1],
                    },
                    {
                        "lease_id": "lease-3",
                        "revision": "2",
                        "state": "current",
                        "detector_runs": result_ids["F"][1:],
                    },
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    common_artifacts = {
        "program-revisions.json": {
            "A-H": {key: ("2" if key == "F" else "1") for key in "ABCDEFGH"}
        },
        "engagements.json": {
            "campaign_id": config.campaign_id,
            "program_ids": list("ABCDEFGH"),
        },
        "policies.json": {program.program_id: program.policy_status for program in programs},
        "detector-registry.json": {
            "selected": sorted({request.detector.detector_id for request in requests})
        },
        "execution-trace.json": {
            "portfolio_order": list(sequence) + ["H-retry"],
            "runs": {key: value for key, value in result_ids.items() if value},
        },
    }
    for name, payload in common_artifacts.items():
        (root / name).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (root / "m53-pass1-report.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    partial = any(program.state == "PARTIAL" for program in programs)
    finalize_orchestrator(
        store,
        config.campaign_id,
        root,
        partial=partial,
        readiness=CampaignReadiness.DEGRADED_COVERAGE,
    )
    return store.snapshot(config.campaign_id), tuple(results), report
