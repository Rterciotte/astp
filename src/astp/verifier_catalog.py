from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class VerificationFamily(StrEnum):
    AUTHORIZATION = "authorization"
    CORS = "cors"
    TLS = "tls"
    COOKIE = "cookie"
    SECURITY_HEADERS = "security_headers"
    INFORMATION_EXPOSURE = "information_exposure"
    CACHE = "cache"
    REDIRECT = "redirect"


class VerifierDefinition(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    family: VerificationFamily
    active_request_required: bool
    state_changing: bool = False
    autonomous_safe: bool = True
    proof_ceiling: str = "likely"


def builtin_verifier_catalog() -> tuple[VerifierDefinition, ...]:
    return (
        VerifierDefinition(
            id="authorization.object-access.v1",
            family=VerificationFamily.AUTHORIZATION,
            active_request_required=True,
        ),
        VerifierDefinition(
            id="cors.headers.v1", family=VerificationFamily.CORS, active_request_required=False
        ),
        VerifierDefinition(
            id="tls.posture.v1", family=VerificationFamily.TLS, active_request_required=False
        ),
        VerifierDefinition(
            id="cookie.flags.v1", family=VerificationFamily.COOKIE, active_request_required=False
        ),
        VerifierDefinition(
            id="security-headers.v1",
            family=VerificationFamily.SECURITY_HEADERS,
            active_request_required=False,
        ),
        VerifierDefinition(
            id="information-exposure.v1",
            family=VerificationFamily.INFORMATION_EXPOSURE,
            active_request_required=False,
        ),
        VerifierDefinition(
            id="cache.sensitive-response.v1",
            family=VerificationFamily.CACHE,
            active_request_required=False,
        ),
        VerifierDefinition(
            id="redirect.reauthorization.v1",
            family=VerificationFamily.REDIRECT,
            active_request_required=False,
            proof_ceiling="informational",
        ),
        VerifierDefinition(
            id="security-headers.csp.v1",
            family=VerificationFamily.SECURITY_HEADERS,
            active_request_required=False,
        ),
        VerifierDefinition(
            id="security-headers.hsts.v1",
            family=VerificationFamily.SECURITY_HEADERS,
            active_request_required=False,
        ),
        VerifierDefinition(
            id="cors.controlled-origin.v1",
            family=VerificationFamily.CORS,
            active_request_required=True,
        ),
        VerifierDefinition(
            id="authorization.identity-differential.v1",
            family=VerificationFamily.AUTHORIZATION,
            active_request_required=True,
        ),
        VerifierDefinition(
            id="cache.variation.v1", family=VerificationFamily.CACHE, active_request_required=True
        ),
    )
