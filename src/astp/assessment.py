from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

from astp.assessment_orchestrator import orchestrate_stored_evidence
from astp.assessment_report import AssessmentReportInput, assemble_assessment_report
from astp.finding_pipeline import CandidatePipelineResult, build_finding_candidates
from astp.findings import FindingSet, correlate_findings
from astp.fingerprint import TechnologyFingerprint
from astp.http_fingerprint import fingerprint_http
from astp.models import Engagement, ProgramOperationalAttestation, TestDefinition
from astp.observation import HttpObservationEvidence, verify_observation_evidence
from astp.signal_normalizer import NormalizedSignal
from astp.target_registry import TargetRegistry


class AssessmentResult(BaseModel):
    schema_version: str = "1"
    session_id: str
    fingerprints: list[TechnologyFingerprint] = Field(default_factory=list)
    signals: list[NormalizedSignal] = Field(default_factory=list)
    candidates: CandidatePipelineResult
    findings: FindingSet
    report_markdown: str
    invalid_evidence_ids: list[str] = Field(default_factory=list)
    network_execution_performed: bool = False


def assess_evidence(
    session_id: str,
    evidence_rows: list[HttpObservationEvidence],
    registry: TargetRegistry,
    engagement: Engagement,
    test: TestDefinition,
    *,
    operational_attestation: ProgramOperationalAttestation | None = None,
    semantic_exclusion_clears: set[str] | None = None,
    requested_rps: float | None = None,
    excluded_finding_terms: set[str] | None = None,
) -> AssessmentResult:
    invalid = [row.evidence_id for row in evidence_rows if not verify_observation_evidence(row)]
    valid_rows = [row for row in evidence_rows if row.evidence_id not in invalid]
    orchestration = orchestrate_stored_evidence(
        session_id,
        valid_rows,
        registry,
        engagement,
        test,
        operational_attestation=operational_attestation,
        semantic_exclusion_clears=semantic_exclusion_clears,
        requested_rps=requested_rps,
    )
    fingerprints: list[TechnologyFingerprint] = []
    signals = orchestration.signals
    for evidence in valid_rows:
        fingerprints.append(fingerprint_http(evidence))
    pipeline = build_finding_candidates(
        signals,
        excluded_finding_terms=excluded_finding_terms,
    )
    findings = correlate_findings(pipeline.candidates)
    report = assemble_assessment_report(
        engagement,
        AssessmentReportInput(
            fingerprints=fingerprints,
            signals=signals,
            findings=findings,
            limitations=(
                ["One or more evidence records failed integrity verification and were excluded."]
                if invalid
                else []
            ),
            evidence_ids=[row.evidence_id for row in valid_rows],
        ),
    )
    return AssessmentResult(
        session_id=session_id,
        fingerprints=fingerprints,
        signals=signals,
        candidates=pipeline,
        findings=findings,
        report_markdown=report,
        invalid_evidence_ids=invalid,
    )


def load_evidence_directory(path: Path) -> list[HttpObservationEvidence]:
    rows: list[HttpObservationEvidence] = []
    if not path.exists():
        return rows
    for candidate in sorted(path.glob("*.json")):
        try:
            rows.append(
                HttpObservationEvidence.model_validate_json(candidate.read_text(encoding="utf-8"))
            )
        except (OSError, ValueError):
            continue
    return rows
