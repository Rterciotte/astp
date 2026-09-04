from datetime import UTC, datetime

from astp.observation import HttpObservationEvidence, RedirectObservation
from astp.result_interpreter import InterpretationSignalKind, interpret_observation


def evidence(status=301):
    return HttpObservationEvidence(
        evidence_id="e",
        action_id="a",
        permit_id="p",
        engagement_id="g",
        test_id="t",
        observed_at=datetime.now(UTC),
        method="GET",
        target="https://example.com",
        status_code=status,
        response_headers={},
        body_sha256="0",
        redirect=RedirectObservation(
            target="https://www.example.com", in_scope=True, same_origin=False
        ),
        evidence_hash="x",
    )


def test_interpreter_emits_redirect_signal():
    result = interpret_observation(evidence())
    assert any(s.kind == InterpretationSignalKind.REDIRECT for s in result.signals)
    assert result.should_expand_surface
