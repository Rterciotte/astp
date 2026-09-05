from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class CircuitState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"


class FailureCircuitBreaker(BaseModel):
    max_consecutive_failures: int = Field(default=2, ge=1, le=100)
    consecutive_failures: int = 0
    state: CircuitState = CircuitState.CLOSED


def record_circuit_result(
    breaker: FailureCircuitBreaker,
    *,
    failed: bool,
) -> FailureCircuitBreaker:
    failures = breaker.consecutive_failures + 1 if failed else 0
    state = (
        CircuitState.OPEN if failures >= breaker.max_consecutive_failures else CircuitState.CLOSED
    )
    return breaker.model_copy(update={"consecutive_failures": failures, "state": state})
