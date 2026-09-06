from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from astp.assessment import load_evidence_directory
from astp.assessment_bundle import AssessmentBundleManifest, verify_assessment_bundle
from astp.evidence_store import verify_evidence_manifest
from astp.lifecycle import verify_audit_chain
from astp.models import Engagement
from astp.program_models import BugBountyProgram, ProgramImportStatus
from astp.target_registry import TargetRegistry


class AcceptanceCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    passed: bool
    detail: str


class BugBountyV1Acceptance(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    program_id: str
    engagement_id: str
    checks: tuple[AcceptanceCheck, ...] = Field(default_factory=tuple)
    evidence_records: int = 0
    target_records: int = 0
    network_actions: int = 0
    permits_consumed: int = 0
    accepted: bool
    network_performed: bool = False


def _check(name: str, passed: bool, detail: str) -> AcceptanceCheck:
    return AcceptanceCheck(name=name, passed=passed, detail=detail)


def evaluate_bug_bounty_v1_acceptance(
    *,
    program: BugBountyProgram,
    engagement: Engagement,
    registry: TargetRegistry,
    evidence_directory: Path,
    evidence_manifest_path: Path,
    audit_path: Path,
    assessment_bundle_directory: Path,
) -> BugBountyV1Acceptance:
    checks: list[AcceptanceCheck] = []

    program_ready = program.status == ProgramImportStatus.READY
    checks.append(
        _check(
            "program_review_complete",
            program_ready,
            (
                "program has no unresolved blocking review issues"
                if program_ready
                else "program still has unresolved blocking review issues"
            ),
        )
    )

    binding = engagement.program
    binding_ok = (
        binding is not None
        and binding.program_id == program.id
        and binding.source_content_sha256 == program.source.content_sha256
    )
    checks.append(
        _check(
            "engagement_program_binding",
            binding_ok,
            (
                "engagement is bound to the reviewed program source revision"
                if binding_ok
                else "engagement/program provenance binding is missing or mismatched"
            ),
        )
    )

    registry_ok = registry.engagement_id == engagement.id
    checks.append(
        _check(
            "target_registry_binding",
            registry_ok,
            (
                "target registry belongs to this engagement"
                if registry_ok
                else "target registry belongs to a different engagement"
            ),
        )
    )
    registry_populated = bool(registry.entries)
    checks.append(
        _check(
            "target_registry_populated",
            registry_populated,
            f"known target records: {len(registry.entries)}",
        )
    )

    evidence_rows = load_evidence_directory(evidence_directory)
    evidence_ok = bool(evidence_rows)
    checks.append(
        _check(
            "stored_evidence_present",
            evidence_ok,
            f"stored HTTP evidence records: {len(evidence_rows)}",
        )
    )

    manifest_exists = evidence_manifest_path.is_file() and evidence_manifest_path.stat().st_size > 0
    if manifest_exists:
        manifest_ok, manifest_detail = verify_evidence_manifest(evidence_manifest_path)
    else:
        manifest_ok, manifest_detail = False, "evidence manifest is missing"
    checks.append(_check("evidence_manifest_integrity", manifest_ok, manifest_detail))

    audit_exists = audit_path.is_file()
    if audit_exists:
        audit_ok, audit_detail = verify_audit_chain(audit_path)
    else:
        audit_ok, audit_detail = False, "audit chain is missing"
    checks.append(_check("audit_chain_integrity", audit_ok, audit_detail))

    summary_path = assessment_bundle_directory / "assessment-summary.json"
    bundle_summary: AssessmentBundleManifest | None = None
    if summary_path.is_file():
        bundle_summary = AssessmentBundleManifest.model_validate_json(
            summary_path.read_text(encoding="utf-8")
        )
        bundle_ok, bundle_blockers = verify_assessment_bundle(assessment_bundle_directory)
        detail = "assessment bundle integrity valid" if bundle_ok else "; ".join(bundle_blockers)
    else:
        bundle_ok = False
        detail = "assessment-summary.json is missing"
    checks.append(_check("assessment_bundle_integrity", bundle_ok, detail))

    bundle_binding_ok = bundle_summary is not None and bundle_summary.engagement_id == engagement.id
    checks.append(
        _check(
            "assessment_bundle_binding",
            bundle_binding_ok,
            (
                "final package belongs to this engagement"
                if bundle_binding_ok
                else "final package belongs to a different or unknown engagement"
            ),
        )
    )

    assessment_complete = bool(bundle_summary and bundle_summary.assessment_complete)
    checks.append(
        _check(
            "network_permit_accounting",
            assessment_complete,
            (
                "declared network actions equal consumed permits"
                if assessment_complete
                else "network action / permit accounting is incomplete"
            ),
        )
    )
    field_network_observed = bool(bundle_summary and bundle_summary.network_actions > 0)
    checks.append(
        _check(
            "authorized_field_execution_recorded",
            field_network_observed,
            (
                f"authorized network actions recorded: {bundle_summary.network_actions}"
                if bundle_summary
                else "no final assessment summary is available"
            ),
        )
    )

    accepted = all(item.passed for item in checks)
    return BugBountyV1Acceptance(
        program_id=program.id,
        engagement_id=engagement.id,
        checks=tuple(checks),
        evidence_records=len(evidence_rows),
        target_records=len(registry.entries),
        network_actions=bundle_summary.network_actions if bundle_summary else 0,
        permits_consumed=bundle_summary.permits_consumed if bundle_summary else 0,
        accepted=accepted,
    )
