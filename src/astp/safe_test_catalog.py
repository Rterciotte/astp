from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from astp.models import RiskClass


class SafeTestKind(str, Enum):
    HEADERS = "headers"
    COOKIES = "cookies"
    CORS = "cors"
    TLS = "tls"


class SafeWebTest(BaseModel):
    id: str
    kind: SafeTestKind
    methods: set[str] = Field(default_factory=lambda: {"HEAD"})
    risk_class: RiskClass = RiskClass.PASSIVE
    state_changing: bool = False
    requires_execution_permit: bool = True


def builtin_safe_web_tests() -> list[SafeWebTest]:
    return [
        SafeWebTest(id="web.headers.v1", kind=SafeTestKind.HEADERS),
        SafeWebTest(id="web.cookies.v1", kind=SafeTestKind.COOKIES),
        SafeWebTest(
            id="web.cors.v1",
            kind=SafeTestKind.CORS,
            methods={"GET", "HEAD"},
            risk_class=RiskClass.SAFE_ACTIVE,
        ),
        SafeWebTest(id="web.tls.v1", kind=SafeTestKind.TLS),
    ]
