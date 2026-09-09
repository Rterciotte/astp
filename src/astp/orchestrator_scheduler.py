from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, Field

from astp.detector_policy import DetectorPolicyContext, DetectorPolicyDecision, decide_detector
from astp.detector_registry import DetectorCapability, VulnerabilityFamily


class DetectorOpportunity(BaseModel):
    program_id: str
    detector_id: str
    target: str
    vulnerability_family: VulnerabilityFamily
    reason: str
    supporting_signals: tuple[str, ...] = ()
    expected_requests: int = Field(ge=0)
    estimated_cost: float = Field(ge=0)
    expected_value: float = Field(ge=0, le=10)
    risk_score: float = Field(ge=0, le=10)
    prerequisites: tuple[str, ...] = ()
    remaining_budget: int = Field(ge=0)
    runtime_available: bool
    policy_decision: DetectorPolicyDecision
    priority_score: float


def rank_opportunity(
    capability: DetectorCapability,
    *,
    program_id: str,
    target: str,
    signals: tuple[str, ...],
    decision: DetectorPolicyDecision,
    remaining_budget: int,
    previous_negative_runs: int = 0,
    remaining_time_ratio: float = 1.0,
) -> DetectorOpportunity:
    frequency = {
        VulnerabilityFamily.IDOR: 9,
        VulnerabilityFamily.REFLECTED_XSS: 8,
        VulnerabilityFamily.SQL_INJECTION: 8,
        VulnerabilityFamily.SECRETS_EXPOSURE: 8,
        VulnerabilityFamily.SECURITY_MISCONFIGURATION: 5,
    }.get(capability.vulnerability_family, 6)
    confidence = min(1.0, 0.25 + len(signals) * 0.2)
    cost = capability.maximum_default_requests / max(1, remaining_budget)
    score = round(
        frequency * confidence
        + min(len(signals), 3)
        - cost * 2
        - previous_negative_runs * 1.5
        + max(0, min(1, remaining_time_ratio)),
        3,
    )
    if not decision.allowed:
        score = -100.0
    return DetectorOpportunity(
        program_id=program_id,
        detector_id=capability.detector_id,
        target=target,
        vulnerability_family=capability.vulnerability_family,
        reason="deterministic frequency, signal, proof proximity, request cost, and prior-negative ranking",
        supporting_signals=signals,
        expected_requests=capability.maximum_default_requests,
        estimated_cost=cost,
        expected_value=float(frequency),
        risk_score=5.0,
        prerequisites=(),
        remaining_budget=remaining_budget,
        runtime_available=capability.field_ready,
        policy_decision=decision,
        priority_score=score,
    )


def weighted_round_robin(
    opportunities: list[DetectorOpportunity], *, limit: int
) -> list[DetectorOpportunity]:
    per_program: dict[str, list[DetectorOpportunity]] = {}
    for item in sorted(
        opportunities, key=lambda row: (-row.priority_score, row.detector_id, row.target)
    ):
        if item.policy_decision.allowed:
            per_program.setdefault(item.program_id, []).append(item)
    output = []
    while per_program and len(output) < limit:
        for program_id in sorted(per_program):
            rows = per_program[program_id]
            if rows:
                output.append(rows.pop(0))
            if not rows:
                del per_program[program_id]
            if len(output) >= limit:
                break
    return output


class RetryDecision(BaseModel):
    retry: bool
    next_retry_at: datetime | None = None
    reason: str


def schedule_retry(
    kind: str, count: int, *, now: datetime | None = None, retry_after_seconds: float | None = None
) -> RetryDecision:
    allowed = {
        "dns_temporary",
        "connection_reset",
        "http_transient",
        "runtime_startup",
        "tool_temporary",
        "rate_limited",
    }
    if kind not in allowed:
        return RetryDecision(retry=False, reason=f"{kind} is not retryable")
    current = now or datetime.now(UTC)
    delay = (
        retry_after_seconds
        if retry_after_seconds is not None
        else min(300, 2**count) + random.Random(f"{kind}:{count}").random()
    )
    return RetryDecision(
        retry=True,
        next_retry_at=current + timedelta(seconds=delay),
        reason="bounded exponential backoff",
    )


def canonical_idempotency_key(**parts: str | None) -> str:
    payload = "|".join(f"{key}={parts[key] or ''}" for key in sorted(parts))
    return hashlib.sha256(payload.encode()).hexdigest()


def effective_rate(*ceilings: float | None) -> float:
    values = [value for value in ceilings if value is not None]
    if not values:
        raise ValueError("at least one conservative rate ceiling is required")
    return min(values)


SIGNAL_DETECTORS = {
    "known_cve": "nuclei.astp-lab-cve.v1",
    "bounded_discovery": "ffuf.discovery-bounded.v1",
    "reflected_parameter": "dalfox.reflected-bounded.v1",
    "sql_parameter": "sqlmap.detect-bounded.v1",
    "dom_xss": "playwright.dom-navigation-field.v1",
    "secret_material": "astp.secret-exposure.v1",
    "object_authorization": "astp.idor-differential.v1",
    "ssrf_callback": "astp.ssrf-oast.v1",
}


def opportunities_from_signals(
    *,
    program_id: str,
    target: str,
    signals: tuple[str, ...],
    registry: tuple[DetectorCapability, ...],
    context: DetectorPolicyContext,
    remaining_budget: int,
) -> list[DetectorOpportunity]:
    """Turn normalized evidence signals into ranked detector work, never blind scans."""
    by_id = {item.detector_id: item for item in registry}
    opportunities = []
    for signal in dict.fromkeys(signals):
        detector_id = SIGNAL_DETECTORS.get(signal)
        capability = by_id.get(detector_id) if detector_id else None
        if capability is None:
            continue
        opportunities.append(
            rank_opportunity(
                capability,
                program_id=program_id,
                target=target,
                signals=(signal,),
                decision=decide_detector(capability, context),
                remaining_budget=remaining_budget,
            )
        )
    return sorted(opportunities, key=lambda item: (-item.priority_score, item.detector_id))
