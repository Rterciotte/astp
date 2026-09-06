from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from astp.active_verifier_registry import (
    ActiveVerifierDefinition,
    ActiveVerifierRisk,
    builtin_active_verifiers,
)
from astp.coordinator_loop import CoordinatorLoopInput, LoopDecision, evaluate_coordinator_loop
from astp.findings import FindingCandidate, FindingSignal, ProofState, correlate_findings
from astp.verification_execution_gate import (
    VerificationExecutionContext,
    evaluate_verification_execution,
)


class RuntimeAdmission(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    image_digest: str
    manifest_valid: bool
    qualified: bool
    missing_probes: tuple[str, ...] = Field(default_factory=tuple)


class RuntimeAdmissionDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    admitted: bool
    runtime_id: str
    image_digest: str
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def admit_qualified_runtime(record: RuntimeAdmission) -> RuntimeAdmissionDecision:
    reasons: list[str] = []
    if not record.image_digest.startswith("sha256:"):
        reasons.append("runtime image is not sha256-bound")
    if not record.manifest_valid:
        reasons.append("runtime qualification evidence manifest is invalid")
    if record.missing_probes:
        reasons.append("runtime qualification probes are incomplete")
    if not record.qualified:
        reasons.append("runtime is not qualified")
    return RuntimeAdmissionDecision(
        admitted=not reasons,
        runtime_id=record.runtime_id,
        image_digest=record.image_digest,
        reasons=tuple(reasons),
    )


class AdaptiveSignalKind(StrEnum):
    AUTHORIZATION_BOUNDARY = "authorization-boundary"
    REDIRECT_BOUNDARY = "redirect-boundary"
    CORS_REVIEW = "cors-review"
    CACHE_REVIEW = "cache-review"


class AdaptiveSignal(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    kind: AdaptiveSignalKind
    target: str
    evidence_id: str
    observation: str
    confidence: float = Field(default=0.7, ge=0, le=1)


def extract_adaptive_signals(
    *,
    target: str,
    evidence_id: str,
    status_code: int,
    response_headers: dict[str, str] | None = None,
    redirect_target: str | None = None,
) -> tuple[AdaptiveSignal, ...]:
    headers = {key.lower(): value for key, value in (response_headers or {}).items()}
    rows: list[AdaptiveSignal] = []

    def add(kind: AdaptiveSignalKind, observation: str, confidence: float = 0.7) -> None:
        digest = hashlib.sha256(
            f"{kind.value}|{target}|{evidence_id}|{observation}".encode()
        ).hexdigest()[:16]
        rows.append(
            AdaptiveSignal(
                id=f"signal-{digest}",
                kind=kind,
                target=target,
                evidence_id=evidence_id,
                observation=observation,
                confidence=confidence,
            )
        )

    if status_code in {401, 403}:
        add(AdaptiveSignalKind.AUTHORIZATION_BOUNDARY, f"HTTP {status_code}", 0.9)
    if redirect_target:
        add(AdaptiveSignalKind.REDIRECT_BOUNDARY, f"redirect to {redirect_target}", 0.8)
    if "access-control-allow-origin" in headers:
        add(
            AdaptiveSignalKind.CORS_REVIEW,
            f"access-control-allow-origin={headers['access-control-allow-origin']}",
        )
    if "cache-control" in headers:
        add(AdaptiveSignalKind.CACHE_REVIEW, f"cache-control={headers['cache-control']}", 0.6)
    return tuple(rows)


class AdaptiveHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    signal_id: str
    target: str
    verifier_id: str
    statement: str
    current_state: ProofState = ProofState.SUSPECTED
    requires_fresh_policy_evaluation: bool = True
    requires_fresh_permit: bool = True


_SIGNAL_VERIFIER = {
    AdaptiveSignalKind.AUTHORIZATION_BOUNDARY: "authorization.object-access.v2",
    AdaptiveSignalKind.REDIRECT_BOUNDARY: "redirect.authorization-boundary.v1",
    AdaptiveSignalKind.CORS_REVIEW: "cors.controlled-origin.v1",
    AdaptiveSignalKind.CACHE_REVIEW: "cache.variation.v1",
}


def signals_to_hypotheses(signals: tuple[AdaptiveSignal, ...]) -> tuple[AdaptiveHypothesis, ...]:
    rows: list[AdaptiveHypothesis] = []
    for signal in signals:
        verifier_id = _SIGNAL_VERIFIER[signal.kind]
        digest = hashlib.sha256(f"{signal.id}|{verifier_id}".encode()).hexdigest()[:16]
        rows.append(
            AdaptiveHypothesis(
                id=f"hyp-{digest}",
                signal_id=signal.id,
                target=signal.target,
                verifier_id=verifier_id,
                statement=(
                    f"Signal {signal.kind.value} warrants bounded verification "
                    f"on {signal.target}"
                ),
            )
        )
    return tuple(rows)


class VerificationCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    hypothesis_id: str
    verifier_id: str
    target: str
    risk: ActiveVerifierRisk
    requires_fresh_permit: bool = True
    requires_exact_approval: bool = False


def build_verification_candidates(
    hypotheses: tuple[AdaptiveHypothesis, ...],
    *,
    registry: tuple[ActiveVerifierDefinition, ...] | None = None,
) -> tuple[VerificationCandidate, ...]:
    definitions = {item.id: item for item in (registry or builtin_active_verifiers())}
    rows: list[VerificationCandidate] = []
    seen: set[tuple[str, str]] = set()
    for hypothesis in hypotheses:
        definition = definitions.get(hypothesis.verifier_id)
        if definition is None:
            continue
        key = (definition.id, hypothesis.target)
        if key in seen:
            continue
        seen.add(key)
        digest = hashlib.sha256(f"{definition.id}|{hypothesis.target}".encode()).hexdigest()[:16]
        rows.append(
            VerificationCandidate(
                id=f"verify-{digest}",
                hypothesis_id=hypothesis.id,
                verifier_id=definition.id,
                target=hypothesis.target,
                risk=definition.risk,
                requires_fresh_permit=definition.requires_fresh_permit,
                requires_exact_approval=definition.risk is ActiveVerifierRisk.STATE_CHANGING,
            )
        )
    return tuple(rows)


class ExactApproval(BaseModel):
    model_config = ConfigDict(frozen=True)

    approval_id: str
    verifier_id: str
    target: str
    action_id: str
    approved: bool = True


def exact_approval_matches(
    approval: ExactApproval | None,
    *,
    verifier_id: str,
    target: str,
    action_id: str,
) -> bool:
    return bool(
        approval
        and approval.approved
        and approval.verifier_id == verifier_id
        and approval.target == target
        and approval.action_id == action_id
    )


class AdaptiveExecutionDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidate_id: str
    executable: bool
    autonomous_execution_allowed: bool
    zero_worker_launch: bool
    zero_network_io: bool
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_adaptive_execution(
    candidate: VerificationCandidate,
    *,
    policy_allowed: bool,
    attestation_fresh: bool,
    permit_id: str | None,
    approval: ExactApproval | None = None,
) -> AdaptiveExecutionDecision:
    definitions = {item.id: item for item in builtin_active_verifiers()}
    definition = definitions[candidate.verifier_id]
    approval_id: str | None = None
    if candidate.requires_exact_approval and exact_approval_matches(
        approval,
        verifier_id=candidate.verifier_id,
        target=candidate.target,
        action_id=candidate.id,
    ):
        approval_id = approval.approval_id if approval else None

    decision = evaluate_verification_execution(
        definition,
        VerificationExecutionContext(
            verifier_id=candidate.verifier_id,
            permit_id=permit_id,
            approval_id=approval_id,
            policy_allowed=policy_allowed,
            attestation_fresh=attestation_fresh,
        ),
    )
    blocked = not decision.executable
    return AdaptiveExecutionDecision(
        candidate_id=candidate.id,
        executable=decision.executable,
        autonomous_execution_allowed=decision.autonomous_execution_allowed,
        zero_worker_launch=blocked,
        zero_network_io=blocked,
        reasons=decision.reasons,
    )


class VerificationEvidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidate_id: str
    evidence_id: str
    target: str
    supports_hypothesis: bool
    dedicated_verifier_satisfied: bool


def progress_proof_state(
    hypothesis: AdaptiveHypothesis,
    evidence: VerificationEvidence,
) -> ProofState:
    if evidence.candidate_id.strip() == "" or evidence.target != hypothesis.target:
        return hypothesis.current_state
    if evidence.supports_hypothesis and evidence.dedicated_verifier_satisfied:
        return ProofState.LIKELY
    return ProofState.SUSPECTED


class AdaptiveCycleResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_admitted: bool
    signal_count: int
    hypothesis_count: int
    verification_count: int
    proof_state: ProofState
    coordinator_decision: LoopDecision
    state_change_without_approval_blocked: bool
    finding_count: int
    report_ready: bool
    operator_review_required: bool
    closure_ready: bool
    trace_hash: str


def run_offline_adaptive_rehearsal() -> AdaptiveCycleResult:
    admission = admit_qualified_runtime(
        RuntimeAdmission(
            runtime_id="playwright",
            image_digest="sha256:" + "1" * 64,
            manifest_valid=True,
            qualified=True,
        )
    )
    signals = extract_adaptive_signals(
        target="http://astp-qualification-lab:8080/account",
        evidence_id="evidence-observation-1",
        status_code=403,
        response_headers={"Cache-Control": "private, no-store"},
    )
    hypotheses = signals_to_hypotheses(signals)
    candidates = build_verification_candidates(hypotheses)
    authorization_candidate = next(
        item for item in candidates if item.verifier_id == "authorization.object-access.v2"
    )
    safe_decision = evaluate_adaptive_execution(
        authorization_candidate,
        policy_allowed=True,
        attestation_fresh=True,
        permit_id="fresh-permit-1",
    )
    verification_evidence = VerificationEvidence(
        candidate_id=authorization_candidate.id,
        evidence_id="evidence-verification-1",
        target=authorization_candidate.target,
        supports_hypothesis=True,
        dedicated_verifier_satisfied=True,
    )
    hypothesis = next(
        item for item in hypotheses if item.verifier_id == authorization_candidate.verifier_id
    )
    proof_state = progress_proof_state(hypothesis, verification_evidence)
    state_definition = next(
        item
        for item in builtin_active_verifiers()
        if item.risk is ActiveVerifierRisk.STATE_CHANGING
    )
    state_candidate = VerificationCandidate(
        id="verify-state-change-demo",
        hypothesis_id=hypothesis.id,
        verifier_id=state_definition.id,
        target=authorization_candidate.target,
        risk=state_definition.risk,
        requires_exact_approval=True,
    )
    state_decision = evaluate_adaptive_execution(
        state_candidate,
        policy_allowed=True,
        attestation_fresh=True,
        permit_id="fresh-permit-2",
        approval=None,
    )
    coordinator = evaluate_coordinator_loop(
        CoordinatorLoopInput(
            accepted_evidence=2,
            new_signals=1,
            pending_verification=0,
            errors=0,
            error_budget=2,
            action_budget_remaining=3,
        )
    )
    finding_candidate = FindingCandidate(
        vulnerability="authorization.boundary.requires-verification",
        asset=authorization_candidate.target,
        endpoint=authorization_candidate.target,
        proof_state=proof_state,
        signals=[
            FindingSignal(
                sensor="adaptive-verification-e2e",
                evidence_id=verification_evidence.evidence_id,
                observation="bounded verifier supplied dedicated supporting evidence",
                confidence=0.8,
            )
        ],
    )
    findings = correlate_findings([finding_candidate]).findings
    payload = {
        "runtime_admitted": admission.admitted,
        "signals": [item.model_dump(mode="json") for item in signals],
        "hypotheses": [item.model_dump(mode="json") for item in hypotheses],
        "safe_execution": safe_decision.model_dump(mode="json"),
        "state_change_execution": state_decision.model_dump(mode="json"),
        "proof_state": proof_state.value,
        "coordinator": coordinator.model_dump(mode="json"),
        "findings": [item.model_dump(mode="json") for item in findings],
    }
    trace_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    return AdaptiveCycleResult(
        runtime_admitted=admission.admitted,
        signal_count=len(signals),
        hypothesis_count=len(hypotheses),
        verification_count=1 if safe_decision.executable else 0,
        proof_state=proof_state,
        coordinator_decision=coordinator.decision,
        state_change_without_approval_blocked=(
            not state_decision.executable
            and state_decision.zero_worker_launch
            and state_decision.zero_network_io
        ),
        finding_count=len(findings),
        report_ready=bool(findings),
        operator_review_required=True,
        closure_ready=False,
        trace_hash=trace_hash,
    )
