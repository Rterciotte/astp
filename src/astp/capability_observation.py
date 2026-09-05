from __future__ import annotations

import hashlib
import json
import socket
import ssl
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, Field

from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.capability_grant import SignedCapabilityGrant, verify_capability_grant
from astp.evidence_store import SensitivityLabel, register_evidence
from astp.lifecycle import consume_execution_permit
from astp.models import Engagement, TestDefinition
from astp.permits import PermitVerificationRequest, SignedExecutionPermit


class CapabilityObservationError(RuntimeError):
    pass


class DnsObservationEvidence(BaseModel):
    schema_version: str = "1"
    evidence_id: str
    permit_id: str
    action_id: str
    hostname: str
    query_type: str
    addresses: list[str] = Field(default_factory=list)
    observed_at: datetime
    evidence_hash: str


class TlsObservationEvidence(BaseModel):
    schema_version: str = "1"
    evidence_id: str
    permit_id: str
    action_id: str
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


def _persist(model: BaseModel, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(model.model_dump_json(indent=2), encoding="utf-8")


def observe_dns(
    grant: SignedCapabilityGrant,
    permit: SignedExecutionPermit,
    action: CapabilityAction,
    engagement: Engagement,
    test: TestDefinition,
    keys: str | bytes | Mapping[str, str | bytes],
    *,
    state_path: Path,
    evidence_path: Path,
    manifest_path: Path,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
    sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL,
    now: datetime | None = None,
) -> DnsObservationEvidence:
    valid, message = verify_capability_grant(grant, permit, action, keys, now=now)
    if not valid:
        raise CapabilityObservationError(message)
    if action.operation not in {
        CapabilityOperation.DNS_A,
        CapabilityOperation.DNS_AAAA,
        CapabilityOperation.DNS_CNAME,
    }:
        raise CapabilityObservationError("action is not a DNS capability operation")
    consumption = consume_execution_permit(
        permit,
        engagement,
        test,
        PermitVerificationRequest(target=action.target, identity=action.identity, now=now),
        keys,
        state_path,
    )
    if not consumption.accepted:
        raise CapabilityObservationError(consumption.message)
    family = socket.AF_INET6 if action.operation == CapabilityOperation.DNS_AAAA else socket.AF_INET
    if action.operation == CapabilityOperation.DNS_CNAME:
        # stdlib getaddrinfo cannot return a canonical CNAME chain reliably; retain the
        # operation in evidence and resolve the endpoint addresses without inventing aliases.
        family = socket.AF_UNSPEC
    try:
        rows = resolver(action.target, action.port or 443, family, socket.SOCK_STREAM)
    except OSError as exc:
        raise CapabilityObservationError(
            f"DNS observation failed: {exc.__class__.__name__}"
        ) from exc
    addresses = sorted({row[4][0] for row in rows if row and len(row) >= 5 and row[4]})
    observed_at = now or datetime.now(UTC)
    payload = {
        "permit_id": permit.payload.permit_id,
        "action_id": action.action_id(),
        "hostname": action.target,
        "query_type": action.operation.value,
        "addresses": addresses,
        "observed_at": observed_at.isoformat(),
    }
    evidence = DnsObservationEvidence(
        evidence_id=str(uuid4()),
        permit_id=permit.payload.permit_id,
        action_id=action.action_id(),
        hostname=action.target,
        query_type=action.operation.value,
        addresses=addresses,
        observed_at=observed_at,
        evidence_hash=_digest(payload),
    )
    _persist(evidence, evidence_path)
    register_evidence(
        manifest_path,
        evidence_path,
        evidence_type="dns.observation.v1",
        evidence_id=evidence.evidence_id,
        permit_id=evidence.permit_id,
        action_id=evidence.action_id,
        sensitivity=sensitivity,
        now=observed_at,
    )
    return evidence


def observe_tls(
    grant: SignedCapabilityGrant,
    permit: SignedExecutionPermit,
    action: CapabilityAction,
    engagement: Engagement,
    test: TestDefinition,
    keys: str | bytes | Mapping[str, str | bytes],
    *,
    state_path: Path,
    evidence_path: Path,
    manifest_path: Path,
    timeout_seconds: float = 10.0,
    connector: Callable[[str, int, float], tuple[str | None, str | None, str | None]] | None = None,
    sensitivity: SensitivityLabel = SensitivityLabel.INTERNAL,
    now: datetime | None = None,
) -> TlsObservationEvidence:
    valid, message = verify_capability_grant(grant, permit, action, keys, now=now)
    if not valid:
        raise CapabilityObservationError(message)
    if action.operation != CapabilityOperation.TLS_HANDSHAKE:
        raise CapabilityObservationError("action is not a TLS handshake operation")
    if action.port is None:
        raise CapabilityObservationError("TLS handshake action requires an explicit port")
    consumption = consume_execution_permit(
        permit,
        engagement,
        test,
        PermitVerificationRequest(target=action.target, identity=action.identity, now=now),
        keys,
        state_path,
    )
    if not consumption.accepted:
        raise CapabilityObservationError(consumption.message)

    def _default_connector(
        host: str, port: int, timeout: float
    ) -> tuple[str | None, str | None, str | None]:
        context = ssl.create_default_context()
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls_sock,
        ):
            protocol = tls_sock.version()
            cipher_data = tls_sock.cipher()
            cipher = cipher_data[0] if cipher_data else None
            cert = tls_sock.getpeercert(binary_form=True)
            cert_hash = hashlib.sha256(cert).hexdigest() if cert else None
            return protocol, cipher, cert_hash

    try:
        protocol, cipher, cert_hash = (connector or _default_connector)(
            action.target, action.port, timeout_seconds
        )
    except (OSError, ssl.SSLError) as exc:
        raise CapabilityObservationError(
            f"TLS observation failed: {exc.__class__.__name__}"
        ) from exc
    observed_at = now or datetime.now(UTC)
    payload = {
        "permit_id": permit.payload.permit_id,
        "action_id": action.action_id(),
        "hostname": action.target,
        "port": action.port,
        "protocol": protocol,
        "cipher": cipher,
        "peer_certificate_sha256": cert_hash,
        "observed_at": observed_at.isoformat(),
    }
    evidence = TlsObservationEvidence(
        evidence_id=str(uuid4()),
        permit_id=permit.payload.permit_id,
        action_id=action.action_id(),
        hostname=action.target,
        port=action.port,
        protocol=protocol,
        cipher=cipher,
        peer_certificate_sha256=cert_hash,
        observed_at=observed_at,
        evidence_hash=_digest(payload),
    )
    _persist(evidence, evidence_path)
    register_evidence(
        manifest_path,
        evidence_path,
        evidence_type="tls.observation.v1",
        evidence_id=evidence.evidence_id,
        permit_id=evidence.permit_id,
        action_id=evidence.action_id,
        sensitivity=sensitivity,
        now=observed_at,
    )
    return evidence
