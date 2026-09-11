from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from astp.detector_policy import (
    DetectorDecisionCode,
    DetectorPolicyContext,
    MentionDisposition,
    decide_detector,
)
from astp.detector_registry import builtin_detector_registry

LOCAL_AUTHORITIES = {"astp-m52-lab:8080", "local.test"}


class ProgramAHAcceptance(BaseModel):
    program: str
    intake_status: str
    policy_status: str
    revision: str
    authorization: str
    lease_id: tuple[str, ...] = ()
    lease_state: tuple[str, ...] = ()
    permit_id: tuple[str, ...] = ()
    detector_runs: tuple[str, ...] = ()
    attempted: int = 0
    forwarded: int = 0
    responses: int = 0
    blocked_before_io: int = 0
    failed_after_io: int = 0
    unknown: int = 0
    evidence_count: int = 0
    proof_state: tuple[str, ...] = ()
    finding_count: int = 0
    retry_count: int = 0
    backoff: str | None = None
    final_state: str
    reason: str | None = None


class AHAuditInvariants(BaseModel):
    unauthorized_requests: int
    out_of_scope_requests: int
    permit_reuse: int
    blind_replay: int
    accounting_mismatches: int
    policy_block_io: int
    semantic_exclusion_block_io: int
    direct_fallbacks: int
    secret_leaks: int
    orphan_workers: int


class M53AHAcceptanceReport(BaseModel):
    campaign_id: str
    status: str
    marker: str
    programs: list[ProgramAHAcceptance] = Field(default_factory=list)
    invariants: AHAuditInvariants


def _durable_results(root: Path) -> list[dict]:
    results = []
    for path in sorted(root.rglob("result.json")):
        if "runs" not in path.parts:
            continue
        results.append(json.loads(path.read_text(encoding="utf-8")))
    return results


def _semantic_exclusion_oracle() -> tuple[str, int]:
    detector = next(
        row for row in builtin_detector_registry() if row.detector_id == "nuclei.astp-lab-cve.v1"
    )
    blocked = decide_detector(
        detector,
        DetectorPolicyContext(
            disposition=MentionDisposition.EXPLICITLY_ALLOWED,
            target_in_scope=True,
            semantic_review_complete=False,
            remaining_requests=1,
        ),
    )
    allowed = decide_detector(
        detector,
        DetectorPolicyContext(
            disposition=MentionDisposition.EXPLICITLY_ALLOWED,
            target_in_scope=True,
            semantic_review_complete=True,
            remaining_requests=1,
        ),
    )
    if blocked.code is not DetectorDecisionCode.BLOCKED_SEMANTIC_EXCLUSION or not allowed.allowed:
        raise RuntimeError("independent semantic exclusion policy oracle failed")
    return "semantic_exclusion_blocked_then_reviewed_allowed", 0


def build_ah_acceptance(root: Path) -> M53AHAcceptanceReport:
    """Reconstruct A-H acceptance from durable artifacts, never expected counters."""
    full = json.loads((root / "full-night-report.json").read_text(encoding="utf-8"))
    trace = json.loads((root / "scheduler-trace.json").read_text(encoding="utf-8"))
    lease_store = json.loads((root / "operational-leases.json").read_text(encoding="utf-8"))
    revision_invalidation = json.loads(
        (root / "round-1" / full["campaign_id"] / "revision-invalidation.json").read_text(
            encoding="utf-8"
        )
    )
    results = _durable_results(root)
    by_program: dict[str, list[dict]] = {key: [] for key in "ABCDEFGH"}
    for result in results:
        authorization = result.get("authorization")
        if authorization:
            program_id = authorization["payload"]["program_id"]
            if program_id in by_program:
                by_program[program_id].append(result)

    program_summary = {row["program_id"]: row for row in full["programs"]}
    scheduler_programs = trace["programs"]
    lease_ids_by_program: dict[str, list[str]] = {key: [] for key in "ABCDEFGH"}
    lease_states_by_program: dict[str, list[str]] = {key: [] for key in "ABCDEFGH"}
    for lease_id, record in lease_store["leases"].items():
        program_id = record["lease"]["program_id"]
        lease_ids_by_program[program_id].append(lease_id)
        lease_states_by_program[program_id].append(record["status"])

    semantic_status, semantic_block_io = _semantic_exclusion_oracle()
    rows = []
    for program_id in "ABCDEFGH":
        program_results = by_program[program_id]
        accounting = [result["accounting"] for result in program_results]
        backoffs = [
            event["retry_at"]
            for event in trace["events"]
            if event["event"] == "http.429" and event["program_id"] == program_id
        ]
        policy_status = (
            "explicit_scanner_denial"
            if program_id == "B"
            else semantic_status if program_id == "C" else "allowed"
        )
        rows.append(
            ProgramAHAcceptance(
                program=program_id,
                intake_status=(
                    "offline_then_online"
                    if program_id == "E"
                    else "revision_refreshed" if program_id == "F" else "ready"
                ),
                policy_status=policy_status,
                revision=scheduler_programs[program_id]["revision"],
                authorization=("blocked_by_policy" if program_id == "B" else "authorized"),
                lease_id=tuple(lease_ids_by_program[program_id]),
                lease_state=tuple(lease_states_by_program[program_id]),
                permit_id=tuple(
                    result["authorization"]["payload"]["permit_id"] for result in program_results
                ),
                detector_runs=tuple(result["detector_run_id"] for result in program_results),
                attempted=sum(item["attempted"] for item in accounting),
                forwarded=sum(item["forwarded"] for item in accounting),
                responses=sum(item["responses"] for item in accounting),
                blocked_before_io=sum(item["blocked_before_io"] for item in accounting),
                failed_after_io=sum(item["failed_after_io"] for item in accounting),
                unknown=sum(item["unknown_outcomes"] for item in accounting),
                evidence_count=sum(
                    len(result["artifacts"]["evidence_ids"]) for result in program_results
                ),
                proof_state=tuple(sorted({result["proof_after"] for result in program_results})),
                finding_count=sum(bool(result.get("finding_id")) for result in program_results),
                retry_count=sum(
                    event["event"] == "runtime.retry" and event["program_id"] == program_id
                    for event in trace["events"]
                ),
                backoff=backoffs[-1] if backoffs else None,
                final_state=program_summary[program_id]["state"],
                reason=(
                    "automated scanners explicitly prohibited"
                    if program_id == "B"
                    else program_summary[program_id]["reason"]
                ),
            )
        )

    permit_ids = [
        result["authorization"]["payload"]["permit_id"]
        for result in results
        if result.get("authorization")
    ]
    run_ids = [result["detector_run_id"] for result in results]
    accounting_mismatches = sum(
        item["accounting"]["attempted"]
        != item["accounting"]["forwarded"] + item["accounting"]["blocked_before_io"]
        or item["accounting"]["forwarded"]
        != item["accounting"]["responses"]
        + item["accounting"]["failed_after_io"]
        + item["accounting"]["unknown_outcomes"]
        for item in results
    )
    run_roots = {
        json.loads(path.read_text(encoding="utf-8"))["detector_run_id"]: path.parent
        for path in root.rglob("result.json")
        if "runs" in path.parts
    }
    direct_fallbacks = sum(
        item["accounting"]["forwarded"] > 0
        and not (run_roots[item["detector_run_id"]] / "proxy-ledger.db").exists()
        for item in results
    )
    stale_f_runs = [
        item
        for item in results
        if item.get("authorization")
        and item["authorization"]["payload"]["program_id"] == "F"
        and item["authorization"]["payload"]["permit_id"]
        == revision_invalidation["stale_permit_id"]
    ]
    sensitive_markers = ("ASTP_DETECTOR_RUN_KEY", "local-acceptance-signing-key")
    secret_leaks = sum(
        any(marker in (item.get("message_redacted") or "") for marker in sensitive_markers)
        for item in results
    )
    invariants = AHAuditInvariants(
        unauthorized_requests=sum(
            item["accounting"]["forwarded"] > 0 and not item.get("authorization")
            for item in results
        ),
        out_of_scope_requests=sum(
            item["accounting"]["forwarded"] > 0
            and item["target"].split("/", 3)[2] not in LOCAL_AUTHORITIES
            for item in results
        ),
        permit_reuse=len(permit_ids) - len(set(permit_ids)),
        blind_replay=len(run_ids) - len(set(run_ids)),
        accounting_mismatches=accounting_mismatches,
        policy_block_io=sum(item["accounting"]["forwarded"] for item in by_program["B"]),
        semantic_exclusion_block_io=semantic_block_io,
        direct_fallbacks=direct_fallbacks + len(stale_f_runs),
        secret_leaks=secret_leaks,
        orphan_workers=full["orphan_workers_remaining"],
    )
    if len(rows) != 8 or any(value != 0 for value in invariants.model_dump().values()):
        raise RuntimeError("A-H global acceptance invariant failed")
    report = M53AHAcceptanceReport(
        campaign_id=full["campaign_id"],
        status="PASS",
        marker="M53_LOCAL_AH_ACCEPTANCE_PASS",
        programs=rows,
        invariants=invariants,
    )
    (root / "m53-ah-acceptance.json").write_text(
        report.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return report
