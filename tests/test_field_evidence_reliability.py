from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from astp.evidence_consumers import consume_http_evidence
from astp.http_fingerprint import fingerprint_http
from astp.observation import (
    BoundaryDecision,
    HttpObservationEvidence,
    RedirectObservation,
    ResponseProvenance,
    ResponseProvenanceSource,
    _canonical_json,
    verify_observation_evidence,
)
from astp.result_interpreter import InterpretationSignalKind, interpret_observation
from astp.web_posture import analyze_http_posture


def _evidence(*, source=ResponseProvenanceSource.TARGET, status=200, headers=None, redirect=None):
    target = source is ResponseProvenanceSource.TARGET
    row = HttpObservationEvidence(
        evidence_id="e-reliability",
        action_id="a",
        permit_id="p",
        engagement_id="g",
        test_id="t",
        observed_at=datetime.now(UTC),
        method="GET",
        target="https://example.test/",
        status_code=status,
        response_headers=headers or {},
        body_sha256=hashlib.sha256(b"").hexdigest(),
        redirect=redirect,
        response_provenance=ResponseProvenance(
            source=source,
            target_response_observed=target,
            synthetic=not target,
            producer="target" if target else "counting_proxy",
            reason=None if target else "request_budget_exhausted",
        ),
        evidence_hash="pending",
    )
    payload = row.model_dump(mode="json", exclude={"evidence_hash"})
    return row.model_copy(
        update={"evidence_hash": hashlib.sha256(_canonical_json(payload)).hexdigest()}
    )


def test_real_target_response_remains_analyzable():
    evidence = _evidence(headers={"Server": "RealLab"})
    assert analyze_http_posture(evidence).signals
    assert fingerprint_http(evidence).observations[0].value == "RealLab"


def test_synthetic_boundary_never_produces_target_attribution(tmp_path):
    evidence = _evidence(
        source=ResponseProvenanceSource.ASTP_BOUNDARY,
        status=403,
        headers={"Server": "BaseHTTP/0.6 Python/3.12.11"},
    )
    assert analyze_http_posture(evidence).signals == []
    assert fingerprint_http(evidence).observations == []
    assert interpret_observation(evidence).signals == []
    path = tmp_path / "boundary.json"
    path.write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
    consumed = consume_http_evidence(path)
    assert consumed.normalized_signals == []
    assert any("NO_TARGET_ATTRIBUTION" in value for value in consumed.limitations)


def test_target_redirect_and_boundary_decision_are_separate():
    evidence = _evidence(
        status=302,
        headers={"Location": "https://outside.invalid/"},
        redirect=RedirectObservation(
            target="https://outside.invalid/", in_scope=False, same_origin=False
        ),
    ).model_copy(
        update={
            "boundary": BoundaryDecision(
                producer="counting_proxy",
                reason="out_of_scope_redirect",
                redirect_followed=False,
            )
        }
    )
    assert evidence.status_code == 302
    assert evidence.redirect.target == "https://outside.invalid/"
    assert evidence.boundary.redirect_followed is False
    assert not any(
        signal.kind is InterpretationSignalKind.AUTH_BOUNDARY
        for signal in interpret_observation(evidence).signals
    )


def test_legacy_evidence_without_any_boundary_marker_fails_closed(tmp_path):
    evidence = _evidence(status=200, headers={"Server": "looks-like-a-target"})
    payload = evidence.model_dump(
        mode="json",
        exclude={"evidence_hash", "response_provenance", "boundary", "response_chain"},
    )
    payload["schema_version"] = "2"
    legacy = evidence.model_copy(
        update={
            "schema_version": "2",
            "response_provenance": None,
            "boundary": None,
            "response_chain": (),
            "evidence_hash": hashlib.sha256(_canonical_json(payload)).hexdigest(),
        }
    )
    path = tmp_path / "legacy.json"
    data = legacy.model_dump(
        mode="json", exclude={"response_provenance", "boundary", "response_chain"}
    )
    path.write_text(__import__("json").dumps(data, default=str), encoding="utf-8")
    parsed = HttpObservationEvidence.model_validate_json(path.read_text(encoding="utf-8"))
    assert verify_observation_evidence(parsed)
    assert analyze_http_posture(parsed).signals == []
    assert fingerprint_http(parsed).observations == []


def test_provenance_round_trip_preserves_integrity(tmp_path):
    evidence = _evidence(headers={"Server": "RealLab"})
    path = tmp_path / "evidence.json"
    path.write_text(evidence.model_dump_json(indent=2), encoding="utf-8")
    parsed = HttpObservationEvidence.model_validate_json(path.read_text(encoding="utf-8"))
    assert parsed.response_provenance.source is ResponseProvenanceSource.TARGET
    assert verify_observation_evidence(parsed)
