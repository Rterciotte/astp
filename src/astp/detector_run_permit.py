from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from typing import Self

from pydantic import BaseModel, ConfigDict, Field


class DetectorRunPermitPayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    permit_id: str
    campaign_id: str
    program_id: str
    program_revision: str
    detector_id: str
    operation: str
    allowed_origin: str
    allowed_path_prefix: str = "/"
    allowed_methods: tuple[str, ...] = ("GET",)
    max_requests: int = Field(ge=1, le=10_000)
    max_concurrency: int = Field(ge=1, le=16)
    max_rps: float = Field(gt=0, le=100)
    issued_at: datetime
    expires_at: datetime
    policy_digest: str
    semantic_review_digest: str
    action_id: str
    detector_run_id: str


class SignedDetectorRunPermit(BaseModel):
    model_config = ConfigDict(frozen=True)

    key_id: str
    payload: DetectorRunPermitPayload
    signature: str

    def verify(self, key: str | bytes, *, now: datetime | None = None) -> Self:
        raw_key = key.encode() if isinstance(key, str) else key
        expected = hmac.new(
            raw_key, self.payload.model_dump_json().encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, self.signature):
            raise ValueError("invalid detector-run permit signature")
        current = now or datetime.now(UTC)
        if current < self.payload.issued_at or current >= self.payload.expires_at:
            raise ValueError("detector-run permit is not currently valid")
        return self


def issue_detector_run_permit(
    payload: DetectorRunPermitPayload, key: str | bytes, *, ttl: timedelta | None = None
) -> SignedDetectorRunPermit:
    if ttl is not None:
        payload = payload.model_copy(update={"expires_at": payload.issued_at + ttl})
    raw_key = key.encode() if isinstance(key, str) else key
    signature = hmac.new(raw_key, payload.model_dump_json().encode(), hashlib.sha256).hexdigest()
    return SignedDetectorRunPermit(key_id="detector-run-v1", payload=payload, signature=signature)
