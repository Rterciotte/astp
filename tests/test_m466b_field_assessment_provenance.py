from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import yaml

from astp.field_assessment_provenance import apply_network_provenance
from astp.observation import HttpObservationEvidence


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _write_success_fixture(tmp_path: Path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_id = "evidence-1"
    evidence_payload = {
        "schema_version": "2",
        "evidence_id": evidence_id,
        "action_id": "a" * 64,
        "sensitivity": "internal",
        "permit_id": "permit-1",
        "engagement_id": "engagement-1",
        "test_id": "field-safe-http-observation-v1",
        "observed_at": datetime.now(UTC).isoformat(),
        "method": "GET",
        "target": "https://smartfit.com/",
        "status_code": 301,
        "reason": "Moved Permanently",
        "response_headers": {"Location": "https://www.smartfit.com.br/"},
        "content_type": "text/html",
        "body_bytes_captured": 0,
        "body_truncated": False,
        "body_sha256": hashlib.sha256(b"").hexdigest(),
        "body_preview": None,
        "redirect": {
            "target": "https://www.smartfit.com.br/",
            "in_scope": True,
            "same_origin": False,
            "requires_new_permit": True,
            "followed": False,
        },
        "resolved_endpoint": None,
        "transport_failure": None,
    }
    evidence_payload["evidence_hash"] = "pending"
    preliminary = HttpObservationEvidence.model_validate(evidence_payload)
    canonical_payload = preliminary.model_dump(mode="json", exclude={"evidence_hash"})
    evidence = preliminary.model_copy(
        update={"evidence_hash": hashlib.sha256(_canonical(canonical_payload)).hexdigest()}
    )
    (evidence_dir / "row.json").write_text(evidence.model_dump_json(), encoding="utf-8")

    session_id = "session-1"
    status = {
        "schema_version": "1",
        "session_id": session_id,
        "completed_actions": 1,
        "failed_actions": 0,
        "permits_issued": 1,
        "execution_succeeded": True,
        "network_state": "HTTP_RESPONSE_OBSERVED",
        "success_evidence_ids": [evidence_id],
        "failure_evidence_ids": [],
        "failure_kinds": [],
        "reason": "response backed",
    }
    status["status_hash"] = "s" * 64
    status_path = tmp_path / f"execution-status-{status['status_hash']}.json"
    status_path.write_text(json.dumps(status), encoding="utf-8")

    result_path = tmp_path / "assessment-result.yaml"
    result_path.write_text(
        yaml.safe_dump(
            {"schema_version": "1", "session_id": session_id, "network_execution_performed": False}
        ),
        encoding="utf-8",
    )
    report_path = tmp_path / "report.md"
    report_path.write_text("# Assessment\n", encoding="utf-8")
    return status_path, evidence_dir, result_path, report_path


def test_response_backed_provenance_sets_network_true(tmp_path):
    status, evidence_dir, result, report = _write_success_fixture(tmp_path)
    provenance, path = apply_network_provenance(
        status_path=status,
        evidence_dir=evidence_dir,
        result_path=result,
        report_path=report,
        output_dir=tmp_path,
    )
    structured = yaml.safe_load(result.read_text(encoding="utf-8"))
    assert provenance.network_state == "HTTP_RESPONSE_OBSERVED"
    assert provenance.network_execution_performed is True
    assert structured["network_execution_performed"] is True
    assert structured["network_state"] == "HTTP_RESPONSE_OBSERVED"
    assert path.exists()
    rendered = report.read_text(encoding="utf-8")
    assert "Network execution performed: **YES**" in rendered
    assert "requires_new_permit=true" in rendered


def test_provenance_rejects_session_mismatch(tmp_path):
    status, evidence_dir, result, report = _write_success_fixture(tmp_path)
    payload = yaml.safe_load(result.read_text(encoding="utf-8"))
    payload["session_id"] = "other-session"
    result.write_text(yaml.safe_dump(payload), encoding="utf-8")
    try:
        apply_network_provenance(
            status_path=status,
            evidence_dir=evidence_dir,
            result_path=result,
            report_path=report,
            output_dir=tmp_path,
        )
    except ValueError as exc:
        assert "binding mismatch" in str(exc)
    else:
        raise AssertionError("session mismatch must fail closed")


def test_provenance_is_idempotent(tmp_path):
    status, evidence_dir, result, report = _write_success_fixture(tmp_path)
    first, first_path = apply_network_provenance(
        status_path=status,
        evidence_dir=evidence_dir,
        result_path=result,
        report_path=report,
        output_dir=tmp_path,
    )
    second, second_path = apply_network_provenance(
        status_path=status,
        evidence_dir=evidence_dir,
        result_path=result,
        report_path=report,
        output_dir=tmp_path,
    )
    assert first.provenance_hash == second.provenance_hash
    assert first_path == second_path
    assert (
        report.read_text(encoding="utf-8").count("ASTP_M466B_RESPONSE_BACKED_NETWORK_PROVENANCE")
        == 1
    )
