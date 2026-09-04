from __future__ import annotations

from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from astp.observation import HttpObservationEvidence


class PostureSignalLevel(str, Enum):
    INFORMATIONAL = "informational"
    REVIEW = "review"


class WebPostureSignal(BaseModel):
    name: str
    level: PostureSignalLevel
    observation: str
    evidence_id: str
    vulnerability_confirmed: bool = False


class WebPostureAssessment(BaseModel):
    schema_version: str = "1"
    target: str
    evidence_id: str
    signals: list[WebPostureSignal] = Field(default_factory=list)


def analyze_http_posture(evidence: HttpObservationEvidence) -> WebPostureAssessment:
    headers = {name.lower(): value for name, value in evidence.response_headers.items()}
    signals: list[WebPostureSignal] = []
    scheme = urlsplit(evidence.target).scheme.lower()
    if scheme == "https" and "strict-transport-security" not in headers:
        signals.append(
            WebPostureSignal(
                name="hsts_absent",
                level=PostureSignalLevel.REVIEW,
                observation="HTTPS response did not include Strict-Transport-Security.",
                evidence_id=evidence.evidence_id,
            )
        )
    if "content-security-policy" not in headers:
        signals.append(
            WebPostureSignal(
                name="csp_absent",
                level=PostureSignalLevel.INFORMATIONAL,
                observation="Response did not include Content-Security-Policy.",
                evidence_id=evidence.evidence_id,
            )
        )
    if "x-content-type-options" not in headers:
        signals.append(
            WebPostureSignal(
                name="x_content_type_options_absent",
                level=PostureSignalLevel.INFORMATIONAL,
                observation="Response did not include X-Content-Type-Options.",
                evidence_id=evidence.evidence_id,
            )
        )
    if "server" in headers and headers["server"] and headers["server"] != "[REDACTED]":
        signals.append(
            WebPostureSignal(
                name="server_header_present",
                level=PostureSignalLevel.INFORMATIONAL,
                observation=f"Server header present: {headers['server']}",
                evidence_id=evidence.evidence_id,
            )
        )
    return WebPostureAssessment(
        target=evidence.target,
        evidence_id=evidence.evidence_id,
        signals=signals,
    )
