from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, field_validator

from astp.capability_action import CapabilityAction
from astp.models import Engagement, TestDefinition
from astp.permits import (
    PermitVerificationRequest,
    SignedExecutionPermit,
    verify_execution_permit,
)

GRANT_SCHEMA_VERSION = "1"


class CapabilityGrantPayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = GRANT_SCHEMA_VERSION
    permit_id: str
    key_id: str | None = None
    engagement_id: str
    test_id: str
    action_id: str
    capability_id: str
    operation: str
    target: str
    port: int | None = None
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("grant timestamps must include a timezone")
        return value


class SignedCapabilityGrant(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str = "hmac-sha256"
    payload: CapabilityGrantPayload
    signature: str


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _select_key(key: str | bytes | Mapping[str, str | bytes], key_id: str | None) -> bytes:
    selected: str | bytes | None
    if isinstance(key, Mapping):
        selected = key.get(key_id) if key_id is not None else None
        if selected is None and len(key) == 1:
            selected = next(iter(key.values()))
        if selected is None:
            raise ValueError("no signing key is available for capability grant key_id")
    else:
        selected = key
    encoded = selected.encode() if isinstance(selected, str) else selected
    if len(encoded) < 32:
        raise ValueError("capability grant signing key must contain at least 32 bytes")
    return encoded


def _signature(payload: CapabilityGrantPayload, key: bytes) -> str:
    raw = _canonical(payload.model_dump(mode="json"))
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def issue_capability_grant(
    permit: SignedExecutionPermit,
    action: CapabilityAction,
    engagement: Engagement,
    test: TestDefinition,
    key: str | bytes | Mapping[str, str | bytes],
    *,
    now: datetime | None = None,
) -> SignedCapabilityGrant:
    current = now or datetime.now(UTC)
    verification = verify_execution_permit(
        permit,
        engagement,
        test,
        PermitVerificationRequest(
            target=action.target,
            http_method=(
                action.operation.value.split(".", 1)[1].upper()
                if action.operation.value.startswith("http.")
                else None
            ),
            identity=action.identity,
            now=current,
        ),
        key,
    )
    if not verification.valid:
        raise ValueError("underlying execution permit failed verification")
    if action.target != permit.payload.target:
        raise ValueError("capability action target must exactly match the execution permit")
    if action.operation.value.startswith("http."):
        expected = action.operation.value.split(".", 1)[1].upper()
        if permit.payload.http_method != expected:
            raise ValueError("HTTP capability operation does not match permit method binding")
    elif permit.payload.http_method is not None:
        raise ValueError("non-HTTP capability actions require a permit without http_method")
    payload = CapabilityGrantPayload(
        permit_id=permit.payload.permit_id,
        key_id=permit.payload.key_id,
        engagement_id=permit.payload.engagement_id,
        test_id=permit.payload.test_id,
        action_id=action.action_id(),
        capability_id=action.capability_id,
        operation=action.operation.value,
        target=action.target,
        port=action.port,
        issued_at=current,
        expires_at=permit.payload.expires_at,
    )
    signing_key = _select_key(key, payload.key_id)
    return SignedCapabilityGrant(payload=payload, signature=_signature(payload, signing_key))


def verify_capability_grant(
    grant: SignedCapabilityGrant,
    permit: SignedExecutionPermit,
    action: CapabilityAction,
    key: str | bytes | Mapping[str, str | bytes],
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    current = now or datetime.now(UTC)
    if grant.payload.permit_id != permit.payload.permit_id:
        return False, "grant is bound to a different execution permit"
    if current < grant.payload.issued_at or current >= grant.payload.expires_at:
        return False, "capability grant is outside its validity window"
    if grant.payload.expires_at != permit.payload.expires_at:
        return False, "grant expiry does not match the underlying permit"
    if grant.payload.action_id != action.action_id():
        return False, "grant action_id does not match the exact requested action"
    if grant.payload.capability_id != action.capability_id:
        return False, "grant capability binding mismatch"
    if grant.payload.operation != action.operation.value:
        return False, "grant operation binding mismatch"
    if grant.payload.target != action.target or grant.payload.port != action.port:
        return False, "grant target binding mismatch"
    try:
        signing_key = _select_key(key, grant.payload.key_id)
    except ValueError as exc:
        return False, str(exc)
    if not hmac.compare_digest(grant.signature, _signature(grant.payload, signing_key)):
        return False, "capability grant signature is invalid"
    return True, "capability grant is valid for this exact action"
