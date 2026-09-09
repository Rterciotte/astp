from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from astp.models import RiskClass


class VulnerabilityFamily(StrEnum):
    REFLECTED_XSS = "reflected_xss"
    STORED_XSS = "stored_xss"
    DOM_XSS = "dom_xss"
    SECRETS_EXPOSURE = "secrets_exposure"
    SENSITIVE_INFORMATION_DISCLOSURE = "sensitive_information_disclosure"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    KNOWN_CVE = "known_cve"
    IDOR = "idor"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_MANAGEMENT = "session_management"
    OAUTH_OIDC = "oauth_oidc"
    MFA_2FA = "mfa_2fa"
    CORS = "cors"
    OPEN_REDIRECT = "open_redirect"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    LFI_RFI = "lfi_rfi"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    DNS_MISCONFIGURATION = "dns_misconfiguration"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    CACHE_POISONING = "cache_poisoning"
    CACHE_DECEPTION = "cache_deception"
    REQUEST_SMUGGLING = "request_smuggling"
    RACE_CONDITION = "race_condition"
    BUSINESS_LOGIC = "business_logic"
    ENDPOINT_DISCOVERY = "endpoint_discovery"
    PARAMETER_DISCOVERY = "parameter_discovery"
    TLS_POSTURE = "tls_posture"


class RuntimeState(StrEnum):
    UNAVAILABLE = "runtime_unavailable"
    INSTALLED = "installed_unqualified"
    QUALIFIED = "qualified"


class ProofRequirement(StrEnum):
    OBSERVATION = "observation"
    REPRODUCTION = "reproduction"
    BROWSER_EXECUTION = "browser_execution"
    DIFFERENTIAL_AUTHORIZATION = "differential_authorization"
    DATABASE_BEHAVIOR = "database_behavior"
    OAST_CALLBACK = "oast_callback"
    VULNERABLE_VERSION = "vulnerable_version"


class DetectorCapability(BaseModel):
    model_config = ConfigDict(frozen=True)

    detector_id: str
    vulnerability_family: VulnerabilityFamily
    engine: str
    operation: str
    protocols: tuple[str, ...] = ("http", "https")
    risk_class: RiskClass
    active: bool
    state_changing: bool = False
    destructive_potential: bool = False
    availability_impact_potential: bool = False
    oast_required: bool = False
    authentication_required: bool = False
    identities_required: int = 0
    browser_required: bool = False
    maximum_default_requests: int = Field(ge=0)
    maximum_default_concurrency: int = Field(ge=1)
    follows_redirects: bool = False
    proof_requirement: ProofRequirement
    autonomous_eligibility: bool = False
    required_runtime: str | None = None
    runtime_state: RuntimeState = RuntimeState.UNAVAILABLE
    field_ready: bool = False
    nightly_enabled: bool = False
    version: str
    provenance: str


def _cap(
    detector_id: str,
    family: VulnerabilityFamily,
    engine: str,
    operation: str,
    proof: ProofRequirement,
    *,
    active: bool = False,
    requests: int = 1,
    runtime: str | None = None,
    state: RuntimeState = RuntimeState.QUALIFIED,
    field: bool = True,
    nightly: bool = False,
    **changes: object,
) -> DetectorCapability:
    return DetectorCapability(
        detector_id=detector_id,
        vulnerability_family=family,
        engine=engine,
        operation=operation,
        risk_class=RiskClass.SAFE_ACTIVE if active else RiskClass.PASSIVE,
        active=active,
        maximum_default_requests=requests,
        maximum_default_concurrency=1,
        proof_requirement=proof,
        autonomous_eligibility=field,
        required_runtime=runtime,
        runtime_state=state,
        field_ready=field,
        nightly_enabled=nightly,
        version="m52.1",
        provenance="builtin:m52",
        **changes,
    )


def builtin_detector_registry() -> tuple[DetectorCapability, ...]:
    unavailable = RuntimeState.UNAVAILABLE
    return (
        _cap(
            "astp.http-posture.v1",
            VulnerabilityFamily.SECURITY_MISCONFIGURATION,
            "astp",
            "http_posture",
            ProofRequirement.OBSERVATION,
            nightly=True,
        ),
        _cap(
            "astp.secret-exposure.v1",
            VulnerabilityFamily.SECRETS_EXPOSURE,
            "astp",
            "static_secret_analysis",
            ProofRequirement.REPRODUCTION,
            nightly=True,
        ),
        _cap(
            "astp.bounded-discovery.v1",
            VulnerabilityFamily.ENDPOINT_DISCOVERY,
            "astp",
            "bounded_discovery",
            ProofRequirement.OBSERVATION,
            nightly=True,
        ),
        _cap(
            "nmap.discovery.v1",
            VulnerabilityFamily.ENDPOINT_DISCOVERY,
            "nmap",
            "external.nmap.discovery",
            ProofRequirement.OBSERVATION,
            active=True,
            requests=32,
            runtime="security-tools",
            state=RuntimeState.QUALIFIED,
            field=False,
        ),
        _cap(
            "nuclei.exposure-safe.v1",
            VulnerabilityFamily.SENSITIVE_INFORMATION_DISCLOSURE,
            "nuclei",
            "external.nuclei.safe",
            ProofRequirement.REPRODUCTION,
            active=True,
            requests=20,
            runtime="nuclei",
            state=unavailable,
            field=False,
        ),
        _cap(
            "nuclei.astp-lab-cve.v1",
            VulnerabilityFamily.KNOWN_CVE,
            "nuclei",
            "external.nuclei.safe",
            ProofRequirement.VULNERABLE_VERSION,
            active=True,
            requests=1,
            runtime="nuclei",
            state=RuntimeState.QUALIFIED,
            field=True,
            nightly=False,
        ),
        _cap(
            "nuclei.misconfiguration-safe.v1",
            VulnerabilityFamily.SECURITY_MISCONFIGURATION,
            "nuclei",
            "external.nuclei.safe",
            ProofRequirement.REPRODUCTION,
            active=True,
            requests=20,
            runtime="nuclei",
            state=unavailable,
            field=False,
        ),
        _cap(
            "nuclei.cve-readonly-safe.v1",
            VulnerabilityFamily.KNOWN_CVE,
            "nuclei",
            "external.nuclei.safe",
            ProofRequirement.VULNERABLE_VERSION,
            active=True,
            requests=20,
            runtime="nuclei",
            state=unavailable,
            field=False,
        ),
        _cap(
            "zap.passive-field.v1",
            VulnerabilityFamily.SECURITY_MISCONFIGURATION,
            "zap",
            "external.zap.passive-field",
            ProofRequirement.REPRODUCTION,
            active=True,
            requests=50,
            runtime="zap",
            state=RuntimeState.INSTALLED,
            field=False,
        ),
        _cap(
            "dalfox.reflected-bounded.v1",
            VulnerabilityFamily.REFLECTED_XSS,
            "dalfox",
            "dalfox.reflected-bounded",
            ProofRequirement.BROWSER_EXECUTION,
            active=True,
            requests=25,
            runtime="dalfox",
            state=RuntimeState.QUALIFIED,
            field=True,
        ),
        _cap(
            "dalfox.dom-analysis.v1",
            VulnerabilityFamily.DOM_XSS,
            "dalfox",
            "dalfox.dom-analysis",
            ProofRequirement.BROWSER_EXECUTION,
            runtime="dalfox",
            state=RuntimeState.INSTALLED,
            field=False,
        ),
        _cap(
            "ffuf.discovery-bounded.v1",
            VulnerabilityFamily.ENDPOINT_DISCOVERY,
            "ffuf",
            "ffuf.discovery-bounded.v1",
            ProofRequirement.OBSERVATION,
            active=True,
            requests=4,
            runtime="ffuf",
            state=RuntimeState.QUALIFIED,
            field=True,
        ),
        _cap(
            "sqlmap.detect-bounded.v1",
            VulnerabilityFamily.SQL_INJECTION,
            "sqlmap",
            "sqlmap.detect-bounded.v1",
            ProofRequirement.DATABASE_BEHAVIOR,
            active=True,
            requests=50,
            runtime="sqlmap",
            state=RuntimeState.QUALIFIED,
            field=True,
        ),
        _cap(
            "playwright.dom-navigation-field.v1",
            VulnerabilityFamily.DOM_XSS,
            "playwright",
            "browser.field-navigate",
            ProofRequirement.BROWSER_EXECUTION,
            active=True,
            requests=1,
            runtime="playwright",
            state=RuntimeState.QUALIFIED,
            field=True,
            browser_required=True,
        ),
        _cap(
            "playwright.auth-field.v1",
            VulnerabilityFamily.SESSION_MANAGEMENT,
            "playwright",
            "browser.auth-workflow",
            ProofRequirement.BROWSER_EXECUTION,
            active=True,
            requests=20,
            runtime="playwright",
            state=RuntimeState.QUALIFIED,
            field=False,
            browser_required=True,
            authentication_required=True,
        ),
        _cap(
            "astp.idor-differential.v1",
            VulnerabilityFamily.IDOR,
            "astp",
            "differential_authorization",
            ProofRequirement.DIFFERENTIAL_AUTHORIZATION,
            active=True,
            requests=3,
            field=True,
            authentication_required=True,
            identities_required=2,
        ),
        _cap(
            "astp.ssrf-oast.v1",
            VulnerabilityFamily.SSRF,
            "astp",
            "oast_verification",
            ProofRequirement.OAST_CALLBACK,
            active=True,
            requests=2,
            field=True,
            oast_required=True,
        ),
    )
