from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from astp.assessment import assess_evidence, load_evidence_directory
from astp.assessment_bundle import AssessmentBundleManifest, build_assessment_bundle
from astp.evidence_consumers import EvidenceConsumerSummary, consume_evidence_directory
from astp.finding_pipeline import build_finding_candidates
from astp.findings import FindingSet, correlate_findings
from astp.models import Engagement, ProgramOperationalAttestation, TestDefinition
from astp.target_registry import TargetRegistry


class StoredAssessmentArtifacts(BaseModel):
    schema_version: str = "1"
    session_id: str
    evidence_records: int
    invalid_evidence_records: int
    normalized_signals: int
    finding_candidates: int
    correlated_findings: int
    report_path: str
    findings_path: str
    consumer_summary_path: str
    assessment_result_path: str
    network_performed: bool = False


def synthesize_consumer_findings(summary: EvidenceConsumerSummary) -> FindingSet:
    signals = [signal for record in summary.records for signal in record.normalized_signals]
    pipeline = build_finding_candidates(signals)
    return correlate_findings(pipeline.candidates)


def run_stored_assessment(
    *,
    session_id: str,
    evidence_directory: Path,
    registry: TargetRegistry,
    engagement: Engagement,
    test: TestDefinition,
    output_directory: Path,
    operational_attestation: ProgramOperationalAttestation | None = None,
    semantic_exclusion_clears: set[str] | None = None,
    requested_rps: float | None = None,
    excluded_finding_terms: set[str] | None = None,
) -> StoredAssessmentArtifacts:
    output_directory.mkdir(parents=True, exist_ok=True)
    evidence_rows = load_evidence_directory(evidence_directory)
    assessment = assess_evidence(
        session_id,
        evidence_rows,
        registry,
        engagement,
        test,
        operational_attestation=operational_attestation,
        semantic_exclusion_clears=semantic_exclusion_clears,
        requested_rps=requested_rps,
        excluded_finding_terms=excluded_finding_terms,
    )
    consumers = consume_evidence_directory(evidence_directory)

    report_path = output_directory / "report.md"
    findings_path = output_directory / "findings.yaml"
    consumers_path = output_directory / "evidence-consumers.yaml"
    result_path = output_directory / "assessment-result.json"

    report_path.write_text(assessment.report_markdown, encoding="utf-8")
    import yaml

    findings_path.write_text(
        yaml.safe_dump(assessment.findings.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    consumers_path.write_text(
        yaml.safe_dump(consumers.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    result_path.write_text(assessment.model_dump_json(indent=2) + "\n", encoding="utf-8")

    return StoredAssessmentArtifacts(
        session_id=session_id,
        evidence_records=len(evidence_rows),
        invalid_evidence_records=len(assessment.invalid_evidence_ids),
        normalized_signals=len(assessment.signals),
        finding_candidates=len(assessment.candidates.candidates),
        correlated_findings=len(assessment.findings.findings),
        report_path=str(report_path),
        findings_path=str(findings_path),
        consumer_summary_path=str(consumers_path),
        assessment_result_path=str(result_path),
    )


def finalize_assessment_package(
    *,
    engagement_id: str,
    report_path: Path,
    findings: FindingSet,
    evidence_manifest_path: Path,
    output_directory: Path,
    network_actions: int = 0,
    permits_consumed: int = 0,
) -> AssessmentBundleManifest:
    evidence_manifest_text = (
        evidence_manifest_path.read_text(encoding="utf-8")
        if evidence_manifest_path.exists()
        else ""
    )
    return build_assessment_bundle(
        output_directory,
        engagement_id=engagement_id,
        report_markdown=report_path.read_text(encoding="utf-8"),
        findings_payload=findings.model_dump(mode="json"),
        evidence_manifest_text=evidence_manifest_text,
        network_actions=network_actions,
        permits_consumed=permits_consumed,
    )
