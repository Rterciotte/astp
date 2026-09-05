from __future__ import annotations

from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from astp.observation import HttpObservationEvidence


class AnalyzerKind(str, Enum):
    HEADER = "header"
    COOKIE = "cookie"
    CORS = "cors"
    TLS = "tls"


class AnalyzerSignal(BaseModel):
    kind: AnalyzerKind
    name: str
    observation: str
    evidence_id: str
    confidence: float = Field(ge=0, le=1)
    informational_only: bool = True
    confirmed_vulnerability: bool = False


class ProtocolAnalysis(BaseModel):
    schema_version: str = "1"
    target: str
    signals: list[AnalyzerSignal] = Field(default_factory=list)


def analyze_protocol_posture(evidence: HttpObservationEvidence) -> ProtocolAnalysis:
    headers = {name.lower(): value for name, value in evidence.response_headers.items()}
    signals: list[AnalyzerSignal] = []

    for header in (
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
    ):
        if header not in headers:
            signals.append(
                AnalyzerSignal(
                    kind=AnalyzerKind.HEADER,
                    name=f"{header}_absent",
                    observation=f"Response did not include {header}.",
                    evidence_id=evidence.evidence_id,
                    confidence=1.0,
                )
            )

    cookie = headers.get("set-cookie")
    if cookie:
        lowered = cookie.lower()
        if "secure" not in lowered:
            signals.append(
                AnalyzerSignal(
                    kind=AnalyzerKind.COOKIE,
                    name="cookie_without_secure_observed",
                    observation="At least one observed Set-Cookie value did not contain Secure.",
                    evidence_id=evidence.evidence_id,
                    confidence=0.65,
                )
            )
        if "httponly" not in lowered:
            signals.append(
                AnalyzerSignal(
                    kind=AnalyzerKind.COOKIE,
                    name="cookie_without_httponly_observed",
                    observation="At least one observed Set-Cookie value did not contain HttpOnly.",
                    evidence_id=evidence.evidence_id,
                    confidence=0.65,
                )
            )

    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        signals.append(
            AnalyzerSignal(
                kind=AnalyzerKind.CORS,
                name="cors_wildcard_with_credentials_header",
                observation=(
                    "Observed Access-Control-Allow-Origin: * together with "
                    "Access-Control-Allow-Credentials: true. Browser behavior and request "
                    "context still require dedicated verification."
                ),
                evidence_id=evidence.evidence_id,
                confidence=0.8,
                informational_only=False,
            )
        )

    if urlsplit(evidence.target).scheme.lower() == "https":
        signals.append(
            AnalyzerSignal(
                kind=AnalyzerKind.TLS,
                name="https_transport_observed",
                observation="Evidence was collected over an HTTPS target.",
                evidence_id=evidence.evidence_id,
                confidence=1.0,
            )
        )
    return ProtocolAnalysis(target=evidence.target, signals=signals)
