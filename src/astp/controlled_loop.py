from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

from astp.circuit_breaker import CircuitState, FailureCircuitBreaker, record_circuit_result
from astp.models import Engagement, ProgramOperationalAttestation, TestDefinition
from astp.operational_guard import evaluate_operational_guard
from astp.origin_budget import OriginBudget, OriginBudgetState, check_and_record_origin
from astp.policy_snapshot import PolicySnapshot, assert_policy_unchanged
from astp.session_ledger import record_completion, reserve_action
from astp.work_queue import WorkQueue, WorkQueueItem


class ControlledStepOutcome(BaseModel):
    queue_id: str
    target: str
    completed: bool
    stopped: bool = False
    reason: str
    permit_id: str | None = None
    evidence_id: str | None = None


class ControlledLoopResult(BaseModel):
    schema_version: str = "1"
    session_id: str
    started_at: datetime
    finished_at: datetime
    outcomes: list[ControlledStepOutcome] = Field(default_factory=list)
    stop_reason: str | None = None
    requests_attempted: int = 0


StepExecutor = Callable[[WorkQueueItem], tuple[str, str]]


def run_controlled_queue(
    queue: WorkQueue,
    engagement: Engagement,
    test: TestDefinition,
    attestation: ProgramOperationalAttestation | None,
    policy_snapshot: PolicySnapshot,
    ledger_path: Path,
    session_id: str,
    executor: StepExecutor,
    *,
    max_actions: int = 3,
    max_requests: int = 3,
    max_errors: int = 1,
    max_actions_per_origin: int = 3,
    breaker: FailureCircuitBreaker | None = None,
) -> ControlledLoopResult:
    started = datetime.now(UTC)
    outcomes: list[ControlledStepOutcome] = []
    origin_state = OriginBudgetState()
    circuit = breaker or FailureCircuitBreaker(max_consecutive_failures=max(1, max_errors))
    stop_reason: str | None = None
    for item in queue.items:
        try:
            assert_policy_unchanged(policy_snapshot, engagement, test)
            guard = evaluate_operational_guard(engagement, attestation)
            if not guard.allowed:
                stop_reason = guard.reason
                break
            origin_state = check_and_record_origin(
                OriginBudget(max_actions_per_origin=max_actions_per_origin),
                origin_state,
                item.target,
            )
            reserve_action(
                ledger_path,
                session_id,
                max_actions=max_actions,
                max_requests=max_requests,
            )
        except ValueError as exc:
            stop_reason = str(exc)
            break

        try:
            permit_id, evidence_id = executor(item)
        # The injected executor is a trust boundary: transport, permit, evidence, or
        # adapter failures must be converted into controlled session state rather
        # than escaping and leaving a reserved ledger action unresolved.
        except Exception as exc:  # noqa: BLE001
            record_completion(ledger_path, session_id, failed=True)
            circuit = record_circuit_result(circuit, failed=True)
            outcomes.append(
                ControlledStepOutcome(
                    queue_id=item.queue_id,
                    target=item.target,
                    completed=False,
                    reason=str(exc),
                )
            )
            if circuit.state == CircuitState.OPEN:
                stop_reason = "failure circuit breaker opened"
                break
            continue

        record_completion(ledger_path, session_id, failed=False)
        circuit = record_circuit_result(circuit, failed=False)
        outcomes.append(
            ControlledStepOutcome(
                queue_id=item.queue_id,
                target=item.target,
                completed=True,
                reason="completed with fresh permit",
                permit_id=permit_id,
                evidence_id=evidence_id,
            )
        )
    return ControlledLoopResult(
        session_id=session_id,
        started_at=started,
        finished_at=datetime.now(UTC),
        outcomes=outcomes,
        stop_reason=stop_reason,
        requests_attempted=len(outcomes),
    )
