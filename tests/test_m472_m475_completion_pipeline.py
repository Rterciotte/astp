from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from astp.assessment_bundle import verify_assessment_bundle
from astp.assessment_workflow import finalize_assessment_package, synthesize_consumer_findings
from astp.cli import app
from astp.evidence_consumers import ContentKind, consume_http_evidence
from astp.evidence_store import SensitivityLabel
from astp.findings import FindingSet
from astp.observation import BodyArtifactReference, HttpObservationEvidence, _canonical_json

runner = CliRunner()


def _write_evidence(tmp_path: Path, *, target: str, content_type: str, body: bytes) -> Path:
    body_path = tmp_path / "sample.body.bin"
    body_path.write_bytes(body)
    body_hash = hashlib.sha256(body).hexdigest()
    row = HttpObservationEvidence(
        evidence_id="e-472",
        action_id="a-472",
        permit_id="p-472",
        engagement_id="eng",
        test_id="test",
        observed_at=datetime.now(UTC),
        method="GET",
        target=target,
        status_code=200,
        response_headers={"Server": "example"},
        content_type=content_type,
        body_bytes_captured=len(body),
        body_sha256=body_hash,
        body_artifact=BodyArtifactReference(
            path=str(body_path),
            sha256=body_hash,
            size_bytes=len(body),
            sensitivity=SensitivityLabel.INTERNAL,
        ),
        evidence_hash="pending",
    )
    payload = row.model_dump(mode="json", exclude={"evidence_hash"})
    row = row.model_copy(
        update={"evidence_hash": hashlib.sha256(_canonical_json(payload)).hexdigest()}
    )
    evidence_path = tmp_path / "sample.json"
    evidence_path.write_text(row.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return evidence_path


def test_m473_javascript_consumer_is_offline_and_non_authorizing(tmp_path: Path) -> None:
    evidence_path = _write_evidence(
        tmp_path,
        target="https://example.com/app.js",
        content_type="application/javascript",
        body=b'const endpoint="/api/profile"; fetch(endpoint);',
    )
    result = consume_http_evidence(evidence_path)
    assert result.content_kind is ContentKind.JAVASCRIPT
    assert result.body_artifact_verified is True
    assert any(
        row.target == "https://example.com/api/profile"
        for row in result.discovered_candidates
    )
    assert all(row.requires_policy_review for row in result.discovered_candidates)
    assert not any(row.network_authorized for row in result.discovered_candidates)


def test_m473_html_consumer_extracts_routes_without_network(tmp_path: Path) -> None:
    evidence_path = _write_evidence(
        tmp_path,
        target="https://example.com/",
        content_type="text/html",
        body=b'<a href="/account">Account</a><script src="/static/app.js"></script>',
    )
    result = consume_http_evidence(evidence_path)
    targets = {row.target for row in result.discovered_candidates}
    assert "https://example.com/account" in targets
    assert "https://example.com/static/app.js" in targets


def test_m473_json_consumer_extracts_url_like_values(tmp_path: Path) -> None:
    evidence_path = _write_evidence(
        tmp_path,
        target="https://example.com/api/bootstrap",
        content_type="application/json",
        body=b'{"profile":"/api/profile","docs":"https://docs.example.com/help"}',
    )
    result = consume_http_evidence(evidence_path)
    targets = {row.target for row in result.discovered_candidates}
    assert "https://example.com/api/profile" in targets
    assert "https://docs.example.com/help" in targets


def test_m474_synthesis_does_not_promote_informational_posture(tmp_path: Path) -> None:
    evidence_path = _write_evidence(
        tmp_path,
        target="https://example.com/",
        content_type="text/html",
        body=b"<html></html>",
    )
    from astp.evidence_consumers import EvidenceConsumerSummary

    summary = EvidenceConsumerSummary(records=[consume_http_evidence(evidence_path)])
    findings = synthesize_consumer_findings(summary)
    assert findings.findings == []


def test_m475_final_package_is_hash_verified(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text("# Report\n", encoding="utf-8")
    evidence_manifest = tmp_path / "evidence-manifest.jsonl"
    evidence_manifest.write_text("", encoding="utf-8")
    output = tmp_path / "bundle"
    manifest = finalize_assessment_package(
        engagement_id="eng",
        report_path=report,
        findings=FindingSet(),
        evidence_manifest_path=evidence_manifest,
        output_directory=output,
        network_actions=1,
        permits_consumed=1,
    )
    valid, blockers = verify_assessment_bundle(output)
    assert manifest.assessment_complete is True
    assert valid is True
    assert blockers == ()


def test_m472_m475_commands_are_exposed() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in (
        "consume-evidence",
        "synthesize-findings",
        "assess-stored-evidence",
        "finalize-assessment",
    ):
        assert name in result.output
