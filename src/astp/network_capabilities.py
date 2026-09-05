from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class NetworkCapabilityKind(str, Enum):
    DNS_LOOKUP = "dns.lookup.v1"
    TLS_HANDSHAKE = "tls.handshake.v1"


class NetworkCapabilityContract(BaseModel):
    id: NetworkCapabilityKind
    allowed_operations: list[str] = Field(default_factory=list)
    requires_execution_permit: bool = True
    state_changing: bool = False
    arbitrary_network: bool = False
    signing_keys_available: bool = False
    default_timeout_seconds: int = 10


def builtin_network_capabilities() -> list[NetworkCapabilityContract]:
    return [
        NetworkCapabilityContract(
            id=NetworkCapabilityKind.DNS_LOOKUP,
            allowed_operations=["A", "AAAA", "CNAME"],
        ),
        NetworkCapabilityContract(
            id=NetworkCapabilityKind.TLS_HANDSHAKE,
            allowed_operations=["certificate", "protocol", "cipher"],
        ),
    ]
