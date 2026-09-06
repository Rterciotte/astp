from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from astp.assessment_bundle import build_assessment_bundle
from astp.bug_bounty_acceptance import evaluate_bug_bounty_v1_acceptance
from astp.cli import app
from astp.evidence_store import SensitivityLabel, register_evidence
from astp.lifecycle import append_audit_event
from astp.models import Constraints, Engagement, ScopeKind, ScopePolicy, ScopeRule
from astp.models import TestDefinition as SecurityTestDefinition
from astp.observation import HttpObservationEvidence, _canonical_json
from astp.program_intake import compile_program
from astp.program_models import (
    BugBountyProgram,
    ProgramOperationalStatus,
    ProgramScopeEntry,
    ProgramSourceSnapshot,
    ProgramVisibility,
    RuleEffect,
    RuleProvenance,
)
from astp.recovery_acceptance import run_recovery_acceptance
from astp.target_discovery import (
    CandidateKind,
    CandidateSafety,
    DiscoveryProvenance,
    TargetCandidate,
)
from astp.target_registry import RegistryEntry, TargetRegistry

runner = CliRunner()
NOW = datetime(2026, 9, 6, 18, 0, tzinfo=UTC)


def _test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="observation.http",
        title="Bounded observation",
        category="observation",
        risk_class="safe_active",
    )


def _engagement() -> Engagement:
    return Engagement(
        id="eng",
        name="Recovery acceptance",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.test")]),
        constraints=Constraints(max_requests_per_second=1),
    )


def _program() -> BugBountyProgram:
    provenance = RuleProvenance(source_type="test", source_text="example.test is in scope")
    return BugBountyProgram(
        id="program-1",
        name="Program One",
        platform="test",
        visibility=ProgramVisibility.PUBLIC,
        operational_status=ProgramOperationalStatus.ONLINE,
        scope=[
            ProgramScopeEntry(
                effect=RuleEffect.ALLOW,
                selector=ScopeRule(kind=ScopeKind.DOMAIN, value="example.test"),
                provenance=provenance,
            )
        ],
        reviewed_max_requests_per_second=1,
        source=ProgramSourceSnapshot(
            source_type="test",
            source_url="https://program.example.test/rules",
            content_sha256="a" * 64,
        ),
    )


def _write_evidence(path: Path, engagement_id: str) -> HttpObservationEvidence:
    row = HttpObservationEvidence(
        evidence_id="e-m480",
        action_id="a-m480",
        permit_id="p-m480",
        engagement_id=engagement_id,
        test_id="observation.http",
        observed_at=NOW,
        method="GET",
        target="https://example.test/",
        status_code=200,
        response_headers={"Content-Type": "text/html"},
        content_type="text/html",
        body_bytes_captured=0,
        body_sha256=hashlib.sha256(b"").hexdigest(),
        evidence_hash="pending",
    )
    payload = row.model_dump(mode="json", exclude={"evidence_hash"})
    row = row.model_copy(
        update={"evidence_hash": hashlib.sha256(_canonical_json(payload)).hexdigest()}
    )
    path.write_text(row.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return row


def _registry(engagement_id: str) -> TargetRegistry:
    provenance = DiscoveryProvenance(
        evidence_id="e-m480",
        source_action_id="a-m480",
        source_target="https://example.test/",
        source_kind=CandidateKind.LINK,
        observed_at=NOW,
    )
    candidate = TargetCandidate(
        id="target-m480",
        canonical_target="https://example.test/",
        display_target="https://example.test/",
        kind=CandidateKind.LINK,
        safety=CandidateSafety.READY_FOR_POLICY,
        in_scope=True,
        same_origin=True,
        reason="acceptance fixture",
        provenance=(provenance,),
        discovered_at=NOW,
    )
    entry = RegistryEntry(
        canonical_target="https://example.test/",
        candidate_ids=[candidate.id],
        provenance=[provenance],
        latest_candidate=candidate,
        first_seen_at=NOW,
        last_seen_at=NOW,
    )
    return TargetRegistry(engagement_id=engagement_id, entries=[entry], updated_at=NOW)


def test_m479_recovery_acceptance_is_fail_closed_and_offline() -> None:
    report = run_recovery_acceptance(_engagement(), _test())
    assert report.accepted is True
    assert report.checkpoint_integrity_enforced is True
    assert report.policy_drift_requires_replan is True
    assert report.tampered_checkpoint_rejected is True
    assert report.network_performed is False
    assert len(report.scenarios) == 6
    assert not any(item.automatic_network_replay_allowed for item in report.scenarios)


def test_m480_acceptance_verifies_complete_stored_chain(tmp_path: Path) -> None:
    program = _program()
    engagement = compile_program(program)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "observation.json"
    _write_evidence(evidence_path, engagement.id)

    manifest_path = tmp_path / "evidence-manifest.jsonl"
    register_evidence(
        manifest_path,
        evidence_path,
        evidence_type="http.observation",
        evidence_id="e-m480",
        permit_id="p-m480",
        action_id="a-m480",
        sensitivity=SensitivityLabel.INTERNAL,
        now=NOW,
    )
    audit_path = tmp_path / "audit.jsonl"
    append_audit_event(
        audit_path,
        "permit_consumed",
        permit_id="p-m480",
        details={"action_id": "a-m480"},
        now=NOW,
    )

    bundle_dir = tmp_path / "bundle"
    build_assessment_bundle(
        bundle_dir,
        engagement_id=engagement.id,
        report_markdown="# Acceptance report\n",
        findings_payload={"findings": []},
        evidence_manifest_text=manifest_path.read_text(encoding="utf-8"),
        network_actions=1,
        permits_consumed=1,
    )

    report = evaluate_bug_bounty_v1_acceptance(
        program=program,
        engagement=engagement,
        registry=_registry(engagement.id),
        evidence_directory=evidence_dir,
        evidence_manifest_path=manifest_path,
        audit_path=audit_path,
        assessment_bundle_directory=bundle_dir,
    )
    assert report.accepted is True
    assert report.network_performed is False
    assert report.network_actions == report.permits_consumed == 1
    assert all(check.passed for check in report.checks)


def test_m480_acceptance_rejects_zero_action_paper_only_assessment(tmp_path: Path) -> None:
    program = _program()
    engagement = compile_program(program)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_path = evidence_dir / "observation.json"
    _write_evidence(evidence_path, engagement.id)
    manifest_path = tmp_path / "evidence-manifest.jsonl"
    register_evidence(
        manifest_path,
        evidence_path,
        evidence_type="http.observation",
        evidence_id="e-m480",
        now=NOW,
    )
    audit_path = tmp_path / "audit.jsonl"
    append_audit_event(audit_path, "offline_only", now=NOW)
    bundle_dir = tmp_path / "bundle"
    build_assessment_bundle(
        bundle_dir,
        engagement_id=engagement.id,
        report_markdown="# Report\n",
        findings_payload={"findings": []},
        evidence_manifest_text=manifest_path.read_text(encoding="utf-8"),
        network_actions=0,
        permits_consumed=0,
    )

    report = evaluate_bug_bounty_v1_acceptance(
        program=program,
        engagement=engagement,
        registry=_registry(engagement.id),
        evidence_directory=evidence_dir,
        evidence_manifest_path=manifest_path,
        audit_path=audit_path,
        assessment_bundle_directory=bundle_dir,
    )
    assert report.accepted is False
    field_check = next(
        item for item in report.checks if item.name == "authorized_field_execution_recorded"
    )
    assert field_check.passed is False


def test_m479_m480_commands_are_exposed() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "recovery-acceptance" in result.output
    assert "bug-bounty-v1-acceptance" in result.output
