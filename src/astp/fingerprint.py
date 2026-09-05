from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class FingerprintKind(str, Enum):
    SERVER = "server"
    CDN = "cdn"
    WAF = "waf"
    FRAMEWORK = "framework"
    CMS = "cms"
    JAVASCRIPT_LIBRARY = "javascript_library"
    API = "api"
    SECURITY_POLICY = "security_policy"
    TLS = "tls"


class FingerprintEvidence(BaseModel):
    kind: FingerprintKind
    value: str
    evidence_id: str
    source: str
    confidence: float = Field(ge=0, le=1)
    version: str | None = None
    confirmed_vulnerability: bool = False


class TechnologyFingerprint(BaseModel):
    schema_version: str = "1"
    target: str
    evidence_ids: list[str] = Field(default_factory=list)
    observations: list[FingerprintEvidence] = Field(default_factory=list)

    @property
    def technologies(self) -> list[str]:
        return sorted({item.value for item in self.observations})
