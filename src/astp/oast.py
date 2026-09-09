from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Protocol

from pydantic import BaseModel

from astp.proof_model import ProofStateV2


class OastPayload(BaseModel):
    payload_id: str
    program_id: str
    target: str
    action_id: str
    permit_id: str
    detector_id: str
    issued_at: datetime


class OastCallback(BaseModel):
    payload_id: str
    protocol: str
    received_at: datetime
    source_hash: str


class OastCorrelation(BaseModel):
    matched: bool
    state: ProofStateV2
    reason: str


class OastProvider(Protocol):
    def issue(self, **bindings: str) -> OastPayload: ...
    def callbacks(self) -> tuple[OastCallback, ...]: ...


class LocalFakeOastProvider:
    def __init__(self) -> None:
        self._payloads: dict[str, OastPayload] = {}
        self._callbacks: list[OastCallback] = []

    def issue(self, **bindings: str) -> OastPayload:
        digest = hashlib.sha256(
            "|".join(bindings[key] for key in sorted(bindings)).encode()
        ).hexdigest()[:20]
        payload = OastPayload(payload_id=f"oast-{digest}", issued_at=datetime.now(UTC), **bindings)
        self._payloads[payload.payload_id] = payload
        return payload

    def record_callback(
        self, payload_id: str, protocol: str, source: str = "local"
    ) -> OastCallback:
        callback = OastCallback(
            payload_id=payload_id,
            protocol=protocol,
            received_at=datetime.now(UTC),
            source_hash=hashlib.sha256(source.encode()).hexdigest(),
        )
        self._callbacks.append(callback)
        return callback

    def callbacks(self) -> tuple[OastCallback, ...]:
        return tuple(self._callbacks)


def correlate_oast(payload: OastPayload, callback: OastCallback) -> OastCorrelation:
    if payload.payload_id != callback.payload_id or callback.received_at < payload.issued_at:
        return OastCorrelation(
            matched=False,
            state=ProofStateV2.SUSPECTED,
            reason="callback does not exactly correlate to issued payload",
        )
    return OastCorrelation(
        matched=True,
        state=ProofStateV2.CONFIRMED,
        reason="callback exactly matched payload and action bindings",
    )
