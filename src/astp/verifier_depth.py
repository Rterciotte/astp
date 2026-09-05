from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from astp.observation import HttpObservationEvidence


class VerifierSignalKind(StrEnum):
    SECURITY_HEADER = "security_header"
    COOKIE_ATTRIBUTE = "cookie_attribute"
    CORS_POLICY = "cors_policy"
    CACHE_POLICY = "cache_policy"
    REDIRECT_POLICY = "redirect_policy"
    INFORMATION_EXPOSURE = "information_exposure"


class VerifierSignal(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: VerifierSignalKind
    verifier_id: str
    target: str
    summary: str
    confidence: float = Field(ge=0.0, le=1.0)
    proof_ceiling: str = "likely"
    confirmed_vulnerability: bool = False
    requires_active_verification: bool = False


def _headers(evidence: HttpObservationEvidence) -> dict[str, str]:
    return {key.lower(): value for key, value in evidence.response_headers.items()}


def verify_stored_http_evidence(evidence: HttpObservationEvidence) -> tuple[VerifierSignal, ...]:
    """Derive conservative posture signals from already-captured HTTP evidence."""
    headers = _headers(evidence)
    signals: list[VerifierSignal] = []

    if "content-security-policy" not in headers:
        signals.append(
            VerifierSignal(
                kind=VerifierSignalKind.SECURITY_HEADER,
                verifier_id="security-headers.csp.v1",
                target=evidence.target,
                summary="Content-Security-Policy header was not observed in the stored response.",
                confidence=0.95,
            )
        )

    if "strict-transport-security" not in headers and evidence.target.lower().startswith(
        "https://"
    ):
        signals.append(
            VerifierSignal(
                kind=VerifierSignalKind.SECURITY_HEADER,
                verifier_id="security-headers.hsts.v1",
                target=evidence.target,
                summary="Strict-Transport-Security header was not observed on this HTTPS response.",
                confidence=0.95,
            )
        )

    allow_origin = headers.get("access-control-allow-origin")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower()
    if allow_origin == "*" and allow_credentials == "true":
        signals.append(
            VerifierSignal(
                kind=VerifierSignalKind.CORS_POLICY,
                verifier_id="cors.headers.v1",
                target=evidence.target,
                summary="Stored headers combine wildcard ACAO with credential allowance.",
                confidence=0.9,
                requires_active_verification=True,
            )
        )

    cache_control = headers.get("cache-control", "").lower()
    if evidence.sensitivity.value == "sensitive" and not any(
        token in cache_control for token in ("no-store", "private")
    ):
        signals.append(
            VerifierSignal(
                kind=VerifierSignalKind.CACHE_POLICY,
                verifier_id="cache.sensitive-response.v1",
                target=evidence.target,
                summary="Sensitive evidence lacks an observed no-store/private cache directive.",
                confidence=0.85,
            )
        )

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    if server or powered_by:
        values = ", ".join(value for value in (server, powered_by) if value)
        signals.append(
            VerifierSignal(
                kind=VerifierSignalKind.INFORMATION_EXPOSURE,
                verifier_id="information-exposure.headers.v1",
                target=evidence.target,
                summary=f"Technology-identifying response headers were observed: {values}",
                confidence=0.9,
            )
        )

    if evidence.redirect is not None and evidence.redirect.requires_new_permit:
        signals.append(
            VerifierSignal(
                kind=VerifierSignalKind.REDIRECT_POLICY,
                verifier_id="redirect.reauthorization.v1",
                target=evidence.target,
                summary="Redirect target requires a separately authorized action.",
                confidence=1.0,
                proof_ceiling="informational",
            )
        )

    return tuple(signals)
