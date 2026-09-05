from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from astp.evidence_replanner import ReplanResult, replan_registry
from astp.http_fingerprint import fingerprint_http
from astp.models import Engagement, ProgramOperationalAttestation, TestDefinition
from astp.observation import HttpObservationEvidence
from astp.protocol_analyzers import analyze_protocol_posture
from astp.session_feedback import SessionFeedback, apply_session_feedback
from astp.signal_normalizer import NormalizedSignal, normalize_signals
from astp.target_registry import TargetRegistry
from astp.web_posture import analyze_http_posture


class EvidenceCycle(BaseModel):
    evidence_id: str
    processed_at: datetime
    fingerprint_count: int
    signal_count: int
    added_targets: int
    new_authorizable_items: int


class OrchestrationResult(BaseModel):
    schema_version: str = "1"
    session_id: str
    registry: TargetRegistry
    signals: list[NormalizedSignal] = Field(default_factory=list)
    cycles: list[EvidenceCycle] = Field(default_factory=list)
    final_plan: ReplanResult | None = None
    network_execution_performed: bool = False


def process_evidence_cycle(
    session_id: str,
    evidence: HttpObservationEvidence,
    registry: TargetRegistry,
    engagement: Engagement,
    test: TestDefinition,
    *,
    semantic_exclusion_clears: set[str] | None = None,
    operational_attestation: ProgramOperationalAttestation | None = None,
    requested_rps: float | None = None,
) -> tuple[SessionFeedback, list[NormalizedSignal], ReplanResult]:
    previous_targets = {item.canonical_target for item in registry.entries}
    fingerprint = fingerprint_http(evidence)
    protocol = analyze_protocol_posture(evidence)
    posture = analyze_http_posture(evidence)
    signals = normalize_signals(fingerprint, protocol, posture)
    feedback = apply_session_feedback(session_id, evidence, engagement, registry)
    replan = replan_registry(
        feedback.registry,
        engagement,
        test,
        previous_targets=previous_targets,
        semantic_exclusion_clears=semantic_exclusion_clears,
        operational_attestation=operational_attestation,
        requested_rps=requested_rps,
    )
    return feedback, signals, replan


def orchestrate_stored_evidence(
    session_id: str,
    evidence_rows: list[HttpObservationEvidence],
    registry: TargetRegistry,
    engagement: Engagement,
    test: TestDefinition,
    *,
    semantic_exclusion_clears: set[str] | None = None,
    operational_attestation: ProgramOperationalAttestation | None = None,
    requested_rps: float | None = None,
) -> OrchestrationResult:
    current = registry
    signals: list[NormalizedSignal] = []
    cycles: list[EvidenceCycle] = []
    final_plan: ReplanResult | None = None
    for evidence in evidence_rows:
        feedback, cycle_signals, final_plan = process_evidence_cycle(
            session_id,
            evidence,
            current,
            engagement,
            test,
            semantic_exclusion_clears=semantic_exclusion_clears,
            operational_attestation=operational_attestation,
            requested_rps=requested_rps,
        )
        current = feedback.registry
        signals.extend(cycle_signals)
        cycles.append(
            EvidenceCycle(
                evidence_id=evidence.evidence_id,
                processed_at=datetime.now(UTC),
                fingerprint_count=sum(
                    1 for row in cycle_signals if row.key.startswith("fingerprint.")
                ),
                signal_count=len(cycle_signals),
                added_targets=feedback.added_targets,
                new_authorizable_items=final_plan.new_authorizable_items,
            )
        )
    return OrchestrationResult(
        session_id=session_id,
        registry=current,
        signals=signals,
        cycles=cycles,
        final_plan=final_plan,
    )
