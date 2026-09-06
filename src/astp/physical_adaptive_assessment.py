from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from astp.evidence_store import register_evidence
from astp.physical_qualification_runner import run_runtime_lab_qualification


class PhysicalAdaptiveStep(BaseModel):
    model_config = ConfigDict(frozen=True)

    stage: Literal["observation", "verification"]
    runtime_id: str
    permit_id: str
    evidence_id: str
    target: str
    action_id: str
    network_execution: str


class PhysicalReplanGate(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Literal["continue", "stop"]
    fresh_permit: bool
    policy_allowed: bool
    attestation_fresh: bool
    reasons: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_physical_replan_gate(
    *,
    previous_permit_id: str,
    next_permit_id: str,
    policy_allowed: bool,
    attestation_fresh: bool,
) -> PhysicalReplanGate:
    reasons: list[str] = []
    fresh_permit = bool(next_permit_id.strip()) and next_permit_id != previous_permit_id
    if not policy_allowed:
        reasons.append("policy drift blocks adaptive continuation")
    if not attestation_fresh:
        reasons.append("stale attestation blocks adaptive continuation")
    if not fresh_permit:
        reasons.append("adaptive continuation requires a fresh permit")
    return PhysicalReplanGate(
        decision="stop" if reasons else "continue",
        fresh_permit=fresh_permit,
        policy_allowed=policy_allowed,
        attestation_fresh=attestation_fresh,
        reasons=tuple(reasons),
    )


class StateChangingLaunchGate(BaseModel):
    model_config = ConfigDict(frozen=True)

    executable: bool
    zero_worker_launch: bool
    zero_network_io: bool
    reason: str


def state_changing_launch_gate(*, exact_approval: bool) -> StateChangingLaunchGate:
    if not exact_approval:
        return StateChangingLaunchGate(
            executable=False,
            zero_worker_launch=True,
            zero_network_io=True,
            reason="exact operator approval is required before worker launch",
        )
    return StateChangingLaunchGate(
        executable=True,
        zero_worker_launch=False,
        zero_network_io=False,
        reason="exact approval is present; policy and permit gates still apply",
    )


class PhysicalAdaptiveTrace(BaseModel):
    model_config = ConfigDict(frozen=True)

    engagement_id: str
    observation: PhysicalAdaptiveStep
    signal: str
    hypothesis: str
    replan_gate: PhysicalReplanGate
    verification: PhysicalAdaptiveStep
    state_change_without_approval: StateChangingLaunchGate
    finding_count: int
    report_ready: bool
    operator_review_required: bool
    closure_ready: bool
    trace_hash: str


def _step(
    stage: Literal["observation", "verification"], row: dict[str, object]
) -> PhysicalAdaptiveStep:
    return PhysicalAdaptiveStep(
        stage=stage,
        runtime_id=str(row["runtime_id"]),
        permit_id=str(row["permit_id"]),
        evidence_id=str(row["evidence_id"]),
        target=str(row["target"]),
        action_id=str(row["action_id"]),
        network_execution=str(row["network_execution"]),
    )


def build_physical_adaptive_trace(
    *,
    observation: PhysicalAdaptiveStep,
    verification: PhysicalAdaptiveStep,
    policy_allowed: bool = True,
    attestation_fresh: bool = True,
) -> PhysicalAdaptiveTrace:
    if observation.stage != "observation" or verification.stage != "verification":
        raise ValueError("physical adaptive trace stages are invalid")
    if observation.target != verification.target:
        raise ValueError("verification target must exactly match the observed target")
    if observation.evidence_id == verification.evidence_id:
        raise ValueError("verification must produce new evidence")
    if (
        observation.network_execution != "PERFORMED"
        or verification.network_execution != "PERFORMED"
    ):
        raise ValueError("physical adaptive trace requires performed local-lab network I/O")

    gate = evaluate_physical_replan_gate(
        previous_permit_id=observation.permit_id,
        next_permit_id=verification.permit_id,
        policy_allowed=policy_allowed,
        attestation_fresh=attestation_fresh,
    )
    if gate.decision != "continue":
        raise ValueError("physical adaptive verification is blocked by the replan gate")

    state_gate = state_changing_launch_gate(exact_approval=False)
    payload = {
        "observation": observation.model_dump(mode="json"),
        "signal": "authorized local HTTP service observed by qualified browser runtime",
        "hypothesis": "a second bounded passive sensor can independently verify the observed surface",
        "replan_gate": gate.model_dump(mode="json"),
        "verification": verification.model_dump(mode="json"),
        "state_change_without_approval": state_gate.model_dump(mode="json"),
        "finding_count": 0,
        "report_ready": True,
        "operator_review_required": True,
        "closure_ready": False,
    }
    trace_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return PhysicalAdaptiveTrace(
        engagement_id="astp-local-qualification",
        observation=observation,
        signal=payload["signal"],
        hypothesis=payload["hypothesis"],
        replan_gate=gate,
        verification=verification,
        state_change_without_approval=state_gate,
        finding_count=0,
        report_ready=True,
        operator_review_required=True,
        closure_ready=False,
        trace_hash=trace_hash,
    )


def persist_physical_adaptive_trace(root: Path, trace: PhysicalAdaptiveTrace) -> Path:
    qroot = root / ".astp" / "qualification"
    directory = qroot / "evidence" / "adaptive-assessment"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{trace.trace_hash}.json"
    path.write_text(
        json.dumps(trace.model_dump(mode="json"), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    register_evidence(
        qroot / "evidence-manifest.jsonl",
        path,
        evidence_type="assessment.physical-adaptive-trace.v1",
        action_id=trace.verification.action_id,
        permit_id=trace.verification.permit_id,
    )
    return path


def run_authorized_local_physical_adaptive_assessment(
    root: Path,
    *,
    signing_key: str,
) -> tuple[PhysicalAdaptiveTrace, Path]:
    observation_row = run_runtime_lab_qualification(
        root,
        runtime="playwright",
        signing_key=signing_key,
        path="/health",
    )
    verification_row = run_runtime_lab_qualification(
        root,
        runtime="zap",
        signing_key=signing_key,
        path="/health",
    )
    trace = build_physical_adaptive_trace(
        observation=_step("observation", observation_row),
        verification=_step("verification", verification_row),
    )
    return trace, persist_physical_adaptive_trace(root, trace)
