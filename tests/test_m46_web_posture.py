from datetime import UTC, datetime

from astp.observation import (
    HttpObservationEvidence,
    ResponseProvenance,
    ResponseProvenanceSource,
)
from astp.web_posture import analyze_http_posture


def test_posture_signals_are_not_confirmed_vulnerabilities():
    e = HttpObservationEvidence(
        evidence_id="e",
        action_id="a",
        permit_id="p",
        engagement_id="g",
        test_id="t",
        observed_at=datetime.now(UTC),
        method="GET",
        target="https://example.com",
        status_code=200,
        response_headers={"Server": "nginx"},
        response_provenance=ResponseProvenance(
            source=ResponseProvenanceSource.TARGET,
            target_response_observed=True,
            synthetic=False,
            producer="target",
        ),
        body_sha256="0",
        evidence_hash="x",
    )
    result = analyze_http_posture(e)
    assert result.signals
    assert all(not signal.vulnerability_confirmed for signal in result.signals)
