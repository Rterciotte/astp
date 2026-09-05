from __future__ import annotations

import hashlib
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, field_validator

from astp.secret_broker import SecretReference


class AuthInjection(StrEnum):
    BEARER = "bearer"
    COOKIE = "cookie"
    HEADER = "header"


class AuthBinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    secret: SecretReference
    injection: AuthInjection
    header_name: str | None = None

    @field_validator("header_name")
    @classmethod
    def validate_header_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned or any(ch in cleaned for ch in "\r\n:"):
            raise ValueError("invalid authentication header name")
        return cleaned


class AuthSessionProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    identity: str
    bindings: tuple[AuthBinding, ...]
    allowed_origins: tuple[str, ...]
    redirects_allowed: bool = False
    raw_secrets_exportable: bool = False


def canonical_origin(target: str) -> str:
    parsed = urlsplit(target)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"} or not host:
        raise ValueError("authenticated target must be an absolute HTTP(S) URL")
    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def build_auth_session_profile(
    identity: str,
    bindings: list[AuthBinding],
    allowed_origins: list[str],
) -> AuthSessionProfile:
    clean_identity = identity.strip()
    if not clean_identity:
        raise ValueError("authentication identity is required")
    origins = tuple(sorted({canonical_origin(origin) for origin in allowed_origins}))
    if not origins:
        raise ValueError("at least one allowed origin is required")
    for binding in bindings:
        if binding.injection == AuthInjection.HEADER and binding.header_name is None:
            raise ValueError("custom header authentication requires header_name")
        secret_origins = {canonical_origin(origin) for origin in binding.secret.allowed_origins}
        if secret_origins and not set(origins).issubset(secret_origins):
            raise ValueError("session origin exceeds secret reference origin binding")
        if binding.secret.allowed_identity not in {None, clean_identity}:
            raise ValueError("secret reference is bound to another identity")
    digest_input = "|".join(
        [clean_identity, *origins, *(binding.secret.id for binding in bindings)]
    )
    digest = hashlib.sha256(digest_input.encode()).hexdigest()[:16]
    return AuthSessionProfile(
        id=f"auth-session-{digest}",
        identity=clean_identity,
        bindings=tuple(bindings),
        allowed_origins=origins,
    )


def assert_session_target_allowed(session: AuthSessionProfile, target: str) -> None:
    if canonical_origin(target) not in set(session.allowed_origins):
        raise ValueError("authenticated session is not allowed for target origin")
