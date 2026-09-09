from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from astp.detector_policy import DetectorPolicyContext, decide_detector
from astp.detector_registry import DetectorCapability, ProofRequirement, RuntimeState
from astp.detector_run_permit import (
    DetectorRunPermitPayload,
    SignedDetectorRunPermit,
    issue_detector_run_permit,
)
from astp.orchestrator_scheduler import DetectorOpportunity
from astp.proof_model import ProofStateV2


class DetectorRunStatus(StrEnum):
    COMPLETED = "completed"
    BLOCKED_BEFORE_IO = "blocked_before_io"
    FAILED = "failed"
    UNKNOWN_OUTCOME = "unknown_outcome"


class DetectorAccounting(BaseModel):
    attempted: int = 0
    forwarded: int = 0
    responses: int = 0
    blocked_before_io: int = 0
    failed_after_io: int = 0
    unknown_outcomes: int = 0
    request_bytes: int = 0
    response_bytes: int = 0

    def validate_invariants(self, ceiling: int) -> None:
        if self.forwarded > ceiling:
            raise ValueError("proxy forwarded more requests than authorized")
        if self.attempted != self.forwarded + self.blocked_before_io:
            raise ValueError("attempted request accounting does not reconcile")
        if self.forwarded != self.responses + self.failed_after_io + self.unknown_outcomes:
            raise ValueError("forwarded request accounting does not reconcile")


class DetectorArtifacts(BaseModel):
    worker_receipt: dict = Field(default_factory=dict)
    raw_output_path: str | None = None
    evidence_ids: tuple[str, ...] = ()


class DetectorAdapterResult(BaseModel):
    accounting: DetectorAccounting
    artifacts: DetectorArtifacts
    proof_state: ProofStateV2
    requirement_satisfied: bool
    candidate_id: str | None = None
    finding_id: str | None = None
    network_started: bool = False
    response_uncertain: bool = False


class DetectorAdapterError(RuntimeError):
    """Typed adapter failure carrying the last authoritative proxy snapshot."""

    def __init__(
        self,
        category: str,
        *,
        accounting: DetectorAccounting | None = None,
        network_started: bool = False,
        retryable: bool = False,
    ) -> None:
        super().__init__(category)
        self.category = category
        self.accounting = accounting or DetectorAccounting()
        self.network_started = network_started
        self.retryable = retryable


class TypedDetectorAdapter(Protocol):
    detector_ids: frozenset[str]

    def execute(
        self, request: DetectorExecutionRequest, permit: SignedDetectorRunPermit, run_root: Path
    ) -> DetectorAdapterResult: ...


class DetectorExecutionJournal(Protocol):
    def create_action(self, request: DetectorExecutionRequest, action_id: str) -> None: ...

    def authorization_persisted(
        self, request: DetectorExecutionRequest, action_id: str, permit_id: str
    ) -> None: ...

    def worker_starting(self, request: DetectorExecutionRequest, action_id: str) -> None: ...

    def result_persisted(
        self, request: DetectorExecutionRequest, result: DetectorRunResult
    ) -> None: ...


class DetectorExecutionRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    campaign_id: str
    campaign_active: bool
    program_id: str
    program_revision: str
    current_program_revision: str
    target: str
    opportunity: DetectorOpportunity
    detector: DetectorCapability
    runtime_id: str
    runtime_digest: str
    runtime_qualification_digest: str
    lease_current: bool
    target_in_scope: bool
    semantic_review_complete: bool
    policy_context: DetectorPolicyContext
    identity_refs: tuple[str, ...] = ()
    global_remaining: int = Field(ge=0)
    program_remaining: int = Field(ge=0)
    detector_remaining: int = Field(ge=0)
    max_rps: float = Field(gt=0)
    proof_requirement: ProofRequirement
    execution_attempt: int = Field(default=1, ge=1)
    parent_candidate_id: str | None = None
    input_artifact_path: str | None = None


class DetectorRunResult(BaseModel):
    detector_run_id: str
    action_id: str
    detector_id: str
    runtime_id: str
    target: str
    status: DetectorRunStatus
    started_at: datetime
    finished_at: datetime
    authorization: SignedDetectorRunPermit | None = None
    accounting: DetectorAccounting = Field(default_factory=DetectorAccounting)
    artifacts: DetectorArtifacts = Field(default_factory=DetectorArtifacts)
    proof_before: ProofStateV2 = ProofStateV2.OBSERVED
    proof_after: ProofStateV2 = ProofStateV2.OBSERVED
    requirement_satisfied: bool = False
    candidate_id: str | None = None
    finding_id: str | None = None
    failure_category: str | None = None
    retryable: bool = False
    message_redacted: str | None = None


class DetectorBudgetStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS reservations(run_id TEXT PRIMARY KEY, campaign_id TEXT, program_id TEXT, detector_id TEXT, reserved INTEGER, consumed INTEGER DEFAULT 0, state TEXT)"
            )

    def reserve(self, run_id: str, request: DetectorExecutionRequest, amount: int) -> None:
        if amount > min(
            request.global_remaining, request.program_remaining, request.detector_remaining
        ):
            raise ValueError("insufficient detector execution budget")
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as db:
            db.execute(
                "INSERT INTO reservations VALUES(?,?,?,?,?,?,?)",
                (
                    run_id,
                    request.campaign_id,
                    request.program_id,
                    request.detector.detector_id,
                    amount,
                    0,
                    "reserved",
                ),
            )

    def reconcile(self, run_id: str, consumed: int) -> None:
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as db:
            row = db.execute(
                "SELECT reserved FROM reservations WHERE run_id=? AND state='reserved'", (run_id,)
            ).fetchone()
            if row is None or consumed > row[0]:
                raise ValueError("budget reservation reconciliation failed")
            db.execute(
                "UPDATE reservations SET consumed=?,state='committed' WHERE run_id=?",
                (consumed, run_id),
            )

    def close_failed(self, run_id: str, consumed: int, *, uncertain: bool) -> None:
        state = "unknown_outcome" if uncertain else "failed"
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as db:
            row = db.execute(
                "SELECT reserved FROM reservations WHERE run_id=? AND state='reserved'",
                (run_id,),
            ).fetchone()
            if row is None or consumed > row[0]:
                raise ValueError("failed budget reservation reconciliation failed")
            db.execute(
                "UPDATE reservations SET consumed=?,state=? WHERE run_id=?",
                (consumed, state, run_id),
            )


class DetectorExecutionService:
    def __init__(
        self,
        root: Path,
        signing_key: str | bytes,
        adapters: tuple[TypedDetectorAdapter, ...],
        journal: DetectorExecutionJournal | None = None,
        lease_validator: Callable[[DetectorExecutionRequest], bool] | None = None,
    ):
        self.root = root
        self.signing_key = signing_key
        self.adapters = {
            detector_id: adapter for adapter in adapters for detector_id in adapter.detector_ids
        }
        self.budgets = DetectorBudgetStore(root / "detector-budgets.db")
        self.journal = journal
        self.lease_validator = lease_validator or (lambda request: request.lease_current)

    def execute(
        self, request: DetectorExecutionRequest, *, now: datetime | None = None
    ) -> DetectorRunResult:
        started = now or datetime.now(UTC)
        key = json.dumps(
            [
                request.campaign_id,
                request.program_id,
                request.program_revision,
                request.detector.detector_id,
                request.target,
                request.execution_attempt,
            ],
            separators=(",", ":"),
        )
        digest = hashlib.sha256(key.encode()).hexdigest()
        run_id, action_id = f"detector-run-{digest[:16]}", f"action-{digest[16:32]}"
        blockers = []
        if not request.campaign_active:
            blockers.append("campaign is not active")
        if request.program_revision != request.current_program_revision:
            blockers.append("program revision changed")
        if not request.lease_current:
            blockers.append("operational lease is stale")
        if request.opportunity.detector_id != request.detector.detector_id:
            blockers.append("opportunity detector binding mismatch")
        if request.opportunity.program_id != request.program_id:
            blockers.append("opportunity program binding mismatch")
        if request.opportunity.target != request.target:
            blockers.append("opportunity target binding mismatch")
        decision = decide_detector(request.detector, request.policy_context)
        if not decision.allowed:
            blockers.append(decision.reason)
        if not request.target_in_scope:
            blockers.append("target is outside scope")
        if not request.semantic_review_complete:
            blockers.append("semantic review is incomplete")
        if (
            request.detector.runtime_state is not RuntimeState.QUALIFIED
            or not request.detector.field_ready
        ):
            blockers.append("runtime is not field-ready")
        if (
            not request.runtime_digest.startswith("sha256:")
            or request.runtime_qualification_digest != request.runtime_digest
        ):
            blockers.append("runtime digest/qualification binding missing")
        adapter = self.adapters.get(request.detector.detector_id)
        if adapter is None:
            blockers.append("typed detector adapter is unavailable")
        if blockers:
            return DetectorRunResult(
                detector_run_id=run_id,
                action_id=action_id,
                detector_id=request.detector.detector_id,
                runtime_id=request.runtime_id,
                target=request.target,
                status=DetectorRunStatus.BLOCKED_BEFORE_IO,
                started_at=started,
                finished_at=datetime.now(UTC),
                failure_category="pre_io_gate",
                message_redacted="; ".join(blockers),
            )
        ceiling = min(
            request.detector.maximum_default_requests,
            request.global_remaining,
            request.program_remaining,
            request.detector_remaining,
        )
        if ceiling <= 0:
            return DetectorRunResult(
                detector_run_id=run_id,
                action_id=action_id,
                detector_id=request.detector.detector_id,
                runtime_id=request.runtime_id,
                target=request.target,
                status=DetectorRunStatus.BLOCKED_BEFORE_IO,
                started_at=started,
                finished_at=datetime.now(UTC),
                failure_category="budget",
                message_redacted="no request budget remains",
            )
        self.budgets.reserve(run_id, request, ceiling)
        if self.journal:
            self.journal.create_action(request, action_id)
        parsed = urlsplit(request.target)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        permit = issue_detector_run_permit(
            DetectorRunPermitPayload(
                permit_id=f"permit-{digest[:20]}",
                campaign_id=request.campaign_id,
                program_id=request.program_id,
                program_revision=request.program_revision,
                detector_id=request.detector.detector_id,
                operation=request.detector.operation,
                allowed_origin=origin,
                allowed_path_prefix=parsed.path or "/",
                allowed_methods=("GET",),
                max_requests=ceiling,
                max_concurrency=request.detector.maximum_default_concurrency,
                max_rps=request.max_rps,
                issued_at=started,
                expires_at=started + timedelta(minutes=2),
                policy_digest=hashlib.sha256(
                    request.policy_context.model_dump_json().encode()
                ).hexdigest(),
                semantic_review_digest=hashlib.sha256(
                    f"{request.program_revision}:{request.target}:{request.semantic_review_complete}".encode()
                ).hexdigest(),
                action_id=action_id,
                detector_run_id=run_id,
            ),
            self.signing_key,
        )
        run_root = self.root / "runs" / run_id
        run_root.mkdir(parents=True, exist_ok=False)
        (run_root / "authorization.json").write_text(
            permit.model_dump_json(indent=2), encoding="utf-8"
        )
        if self.journal:
            self.journal.authorization_persisted(request, action_id, permit.payload.permit_id)
        try:
            if not self.lease_validator(request):
                self.budgets.close_failed(run_id, 0, uncertain=False)
                result = DetectorRunResult(
                    detector_run_id=run_id,
                    action_id=action_id,
                    detector_id=request.detector.detector_id,
                    runtime_id=request.runtime_id,
                    target=request.target,
                    status=DetectorRunStatus.BLOCKED_BEFORE_IO,
                    started_at=started,
                    finished_at=datetime.now(UTC),
                    authorization=permit,
                    failure_category="lease_revoked_before_launch",
                    message_redacted="operational lease is no longer current",
                )
                self._persist_result(run_root, result)
                if self.journal:
                    self.journal.result_persisted(request, result)
                return result
            if self.journal:
                self.journal.worker_starting(request, action_id)
            output = adapter.execute(request, permit, run_root)
            output.accounting.validate_invariants(ceiling)
            if output.response_uncertain:
                self.budgets.close_failed(run_id, output.accounting.forwarded, uncertain=True)
            else:
                self.budgets.reconcile(run_id, output.accounting.forwarded)
            status = (
                DetectorRunStatus.UNKNOWN_OUTCOME
                if output.response_uncertain
                else DetectorRunStatus.COMPLETED
            )
            result = DetectorRunResult(
                detector_run_id=run_id,
                action_id=action_id,
                detector_id=request.detector.detector_id,
                runtime_id=request.runtime_id,
                target=request.target,
                status=status,
                started_at=started,
                finished_at=datetime.now(UTC),
                authorization=permit,
                accounting=output.accounting,
                artifacts=output.artifacts,
                proof_before=(
                    ProofStateV2.CANDIDATE if request.parent_candidate_id else ProofStateV2.OBSERVED
                ),
                proof_after=output.proof_state,
                requirement_satisfied=output.requirement_satisfied,
                candidate_id=output.candidate_id,
                finding_id=output.finding_id,
            )
            self._persist_result(run_root, result)
            if self.journal:
                self.journal.result_persisted(request, result)
            return result
        except DetectorAdapterError as exc:
            uncertain = exc.network_started and (
                exc.accounting.forwarded > exc.accounting.responses
            )
            self.budgets.close_failed(run_id, exc.accounting.forwarded, uncertain=uncertain)
            result = DetectorRunResult(
                detector_run_id=run_id,
                action_id=action_id,
                detector_id=request.detector.detector_id,
                runtime_id=request.runtime_id,
                target=request.target,
                status=(
                    DetectorRunStatus.UNKNOWN_OUTCOME if uncertain else DetectorRunStatus.FAILED
                ),
                started_at=started,
                finished_at=datetime.now(UTC),
                authorization=permit,
                accounting=exc.accounting,
                failure_category=exc.category,
                retryable=exc.retryable and not uncertain,
                message_redacted=exc.category,
            )
            self._persist_result(run_root, result)
            if self.journal:
                self.journal.result_persisted(request, result)
            return result
        except Exception as exc:  # noqa: BLE001 - production boundary must persist failures
            self.budgets.close_failed(run_id, 0, uncertain=False)
            result = DetectorRunResult(
                detector_run_id=run_id,
                action_id=action_id,
                detector_id=request.detector.detector_id,
                runtime_id=request.runtime_id,
                target=request.target,
                status=DetectorRunStatus.FAILED,
                started_at=started,
                finished_at=datetime.now(UTC),
                authorization=permit,
                failure_category="adapter_failure",
                retryable=True,
                message_redacted=type(exc).__name__,
            )
            self._persist_result(run_root, result)
            if self.journal:
                self.journal.result_persisted(request, result)
            return result

    @staticmethod
    def _persist_result(run_root: Path, result: DetectorRunResult) -> None:
        (run_root / "result.json").write_text(
            result.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
