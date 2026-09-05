from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CapabilityOperation(StrEnum):
    DNS_A = "dns.a"
    DNS_AAAA = "dns.aaaa"
    DNS_CNAME = "dns.cname"
    TLS_HANDSHAKE = "tls.handshake"
    HTTP_GET = "http.get"
    HTTP_HEAD = "http.head"


class CapabilityAction(BaseModel):
    """Canonical, exact network action proposed by the control plane."""

    model_config = ConfigDict(frozen=True)

    capability_id: str
    operation: CapabilityOperation
    target: str
    port: int | None = Field(default=None, ge=1, le=65535)
    identity: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def nonempty_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("capability action target must not be empty")
        return value

    def action_id(self) -> str:
        payload = self.model_dump(mode="json")
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(raw).hexdigest()
