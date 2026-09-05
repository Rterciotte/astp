from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, Field


class SecretKind(str, Enum):
    SESSION_COOKIE = "session_cookie"
    API_TOKEN = "api_token"
    BASIC_AUTH = "basic_auth"
    CLIENT_CERTIFICATE = "client_certificate"


class SecretReference(BaseModel):
    id: str
    kind: SecretKind
    provider: str
    locator: str
    allowed_origins: list[str] = Field(default_factory=list)
    allowed_identity: str | None = None
    exportable: bool = False


def build_secret_reference(
    kind: SecretKind,
    provider: str,
    locator: str,
    *,
    allowed_origins: list[str] | None = None,
    allowed_identity: str | None = None,
) -> SecretReference:
    if any(token in locator.lower() for token in ("bearer ", "password=", "token=")):
        raise ValueError("secret locator must be a reference, not a raw credential")
    digest = hashlib.sha256(f"{kind.value}|{provider}|{locator}".encode()).hexdigest()[:16]
    return SecretReference(
        id=f"secret-ref-{digest}",
        kind=kind,
        provider=provider,
        locator=locator,
        allowed_origins=sorted(set(allowed_origins or [])),
        allowed_identity=allowed_identity,
    )
