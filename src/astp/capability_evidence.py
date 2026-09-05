from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from astp.observation import HttpObservationEvidence


class DnsEvidence(BaseModel):
    schema_version: str = "1"
    evidence_id: str
    source_evidence_id: str
    hostname: str
    addresses: list[str] = Field(default_factory=list)
    observed_at: datetime
    evidence_hash: str


class TlsEvidence(BaseModel):
    schema_version: str = "1"
    evidence_id: str
    source_evidence_id: str
    hostname: str
    port: int
    protocol: str | None = None
    cipher: str | None = None
    peer_certificate_sha256: str | None = None
    observed_at: datetime
    evidence_hash: str


def _digest(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def derive_network_capability_evidence(
    evidence: HttpObservationEvidence,
) -> tuple[DnsEvidence | None, TlsEvidence | None]:
    endpoint = evidence.resolved_endpoint
    if endpoint is None:
        return None, None
    now = datetime.now(UTC)
    dns_payload = {
        "source": evidence.evidence_id,
        "hostname": endpoint.hostname,
        "addresses": list(endpoint.addresses),
    }
    dns = DnsEvidence(
        evidence_id=f"dns-{_digest(dns_payload)[:16]}",
        source_evidence_id=evidence.evidence_id,
        hostname=endpoint.hostname,
        addresses=list(endpoint.addresses),
        observed_at=now,
        evidence_hash=_digest(dns_payload),
    )
    tls = None
    if endpoint.tls_protocol or endpoint.tls_cipher or endpoint.peer_certificate_sha256:
        tls_payload = {
            "source": evidence.evidence_id,
            "hostname": endpoint.hostname,
            "port": endpoint.port,
            "protocol": endpoint.tls_protocol,
            "cipher": endpoint.tls_cipher,
            "certificate": endpoint.peer_certificate_sha256,
        }
        tls = TlsEvidence(
            evidence_id=f"tls-{_digest(tls_payload)[:16]}",
            source_evidence_id=evidence.evidence_id,
            hostname=endpoint.hostname,
            port=endpoint.port,
            protocol=endpoint.tls_protocol,
            cipher=endpoint.tls_cipher,
            peer_certificate_sha256=endpoint.peer_certificate_sha256,
            observed_at=now,
            evidence_hash=_digest(tls_payload),
        )
    return dns, tls
