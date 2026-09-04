from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from astp.observation import HttpObservationEvidence


class InterpretationSignalKind(str, Enum):
    REDIRECT = "redirect"
    AUTH_BOUNDARY = "auth_boundary"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"
    CONTENT_TYPE = "content_type"
    BODY_TRUNCATED = "body_truncated"


class InterpretationSignal(BaseModel):
    kind: InterpretationSignalKind
    value: str
    confidence: float = Field(default=1.0, ge=0, le=1)


class ObservationInterpretation(BaseModel):
    schema_version: str = "1"
    evidence_id: str
    target: str
    signals: list[InterpretationSignal] = Field(default_factory=list)
    should_expand_surface: bool = False
    requires_human_review: bool = False


def interpret_observation(evidence: HttpObservationEvidence) -> ObservationInterpretation:
    signals: list[InterpretationSignal] = []
    if evidence.redirect is not None:
        signals.append(
            InterpretationSignal(
                kind=InterpretationSignalKind.REDIRECT,
                value=evidence.redirect.target,
            )
        )
    if evidence.status_code in {401, 403}:
        signals.append(
            InterpretationSignal(
                kind=InterpretationSignalKind.AUTH_BOUNDARY,
                value=str(evidence.status_code),
            )
        )
    elif 400 <= evidence.status_code < 500:
        signals.append(
            InterpretationSignal(
                kind=InterpretationSignalKind.CLIENT_ERROR,
                value=str(evidence.status_code),
            )
        )
    elif evidence.status_code >= 500:
        signals.append(
            InterpretationSignal(
                kind=InterpretationSignalKind.SERVER_ERROR,
                value=str(evidence.status_code),
            )
        )
    if evidence.content_type:
        signals.append(
            InterpretationSignal(
                kind=InterpretationSignalKind.CONTENT_TYPE,
                value=evidence.content_type,
            )
        )
    if evidence.body_truncated:
        signals.append(
            InterpretationSignal(
                kind=InterpretationSignalKind.BODY_TRUNCATED,
                value="true",
            )
        )
    return ObservationInterpretation(
        evidence_id=evidence.evidence_id,
        target=evidence.target,
        signals=signals,
        should_expand_surface=evidence.redirect is not None or bool(evidence.body_preview),
        requires_human_review=evidence.status_code >= 500,
    )
