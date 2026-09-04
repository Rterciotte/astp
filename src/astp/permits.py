from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from astp.authorization import AuthorizationRequest, authorize_test
from astp.models import Decision, Engagement, RiskClass, TestDefinition

PERMIT_SCHEMA_VERSION = "3"
DEFAULT_PERMIT_TTL_SECONDS = 300
MAX_PERMIT_TTL_SECONDS = 900
MIN_SIGNING_KEY_BYTES = 32


class PermitCheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"


class PermitCheck(BaseModel):
    name: str
    status: PermitCheckStatus
    message: str


class ExecutionPermitPayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = PERMIT_SCHEMA_VERSION
    permit_id: str
    key_id: str | None = None
    issuer: str
    engagement_id: str
    test_id: str
    risk_class: RiskClass
    target: str
    http_method: str | None = None
    identity: str | None = None
    max_requests_per_second: float = Field(gt=0, le=1000)
    approval_ids: tuple[str, ...] = ()
    operational_attestation_id: str | None = None
    policy_digest: str
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("permit timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> ExecutionPermitPayload:
        if self.expires_at <= self.issued_at:
            raise ValueError("permit expires_at must be after issued_at")
        return self


class SignedExecutionPermit(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str = "hmac-sha256"
    payload: ExecutionPermitPayload
    signature: str


class PermitVerificationRequest(BaseModel):
    target: str
    http_method: str | None = None
    identity: str | None = None
    requested_requests_per_second: float | None = Field(default=None, gt=0, le=1000)
    now: datetime | None = None


class PermitVerificationResult(BaseModel):
    valid: bool
    checks: list[PermitCheck] = Field(default_factory=list)


def _canonical_json(data: object) -> bytes:
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _model_payload(model: BaseModel) -> dict[str, object]:
    return model.model_dump(mode="json")


def policy_digest(engagement: Engagement, test: TestDefinition) -> str:
    payload = {
        "engagement": _model_payload(engagement),
        "test": _model_payload(test),
    }
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _signing_key(key: str | bytes) -> bytes:
    encoded = key.encode("utf-8") if isinstance(key, str) else key
    if len(encoded) < MIN_SIGNING_KEY_BYTES:
        raise ValueError(f"permit signing key must contain at least {MIN_SIGNING_KEY_BYTES} bytes")
    return encoded


def _signature(payload: ExecutionPermitPayload, key: str | bytes) -> str:
    encoded_key = _signing_key(key)
    data = _model_payload(payload)
    if payload.schema_version == "1":
        data.pop("key_id", None)
    if payload.schema_version in {"1", "2"}:
        data.pop("operational_attestation_id", None)
    message = _canonical_json(data)
    return hmac.new(encoded_key, message, hashlib.sha256).hexdigest()


def issue_execution_permit(
    engagement: Engagement,
    test: TestDefinition,
    request: AuthorizationRequest,
    key: str | bytes,
    *,
    ttl_seconds: int = DEFAULT_PERMIT_TTL_SECONDS,
    issuer: str = "astp-policy-engine",
    key_id: str = "local-v1",
    now: datetime | None = None,
) -> SignedExecutionPermit:
    authorization = authorize_test(engagement, test, request)
    if authorization.decision != Decision.ALLOW:
        raise ValueError(
            "execution permits can only be issued when policy evaluation returns ALLOW"
        )
    if authorization.effective_max_requests_per_second is None:
        raise ValueError("authorization result is missing an effective rate limit")
    if ttl_seconds < 1 or ttl_seconds > MAX_PERMIT_TTL_SECONDS:
        raise ValueError(f"permit TTL must be between 1 and {MAX_PERMIT_TTL_SECONDS} seconds")

    current = now or datetime.now(UTC)
    expires_at = current + timedelta(seconds=ttl_seconds)
    if authorization.operational_status_valid_until is not None:
        expires_at = min(expires_at, authorization.operational_status_valid_until)
    if expires_at <= current:
        raise ValueError("program operational attestation expires before permit issuance")

    payload = ExecutionPermitPayload(
        permit_id=str(uuid4()),
        key_id=key_id,
        issuer=issuer,
        engagement_id=engagement.id,
        test_id=test.id,
        risk_class=test.risk_class,
        target=request.target,
        http_method=request.http_method.upper() if request.http_method else None,
        identity=request.identity,
        max_requests_per_second=authorization.effective_max_requests_per_second,
        approval_ids=tuple(sorted(authorization.approval_ids)),
        operational_attestation_id=authorization.operational_attestation_id,
        policy_digest=policy_digest(engagement, test),
        issued_at=current,
        expires_at=expires_at,
    )
    return SignedExecutionPermit(
        payload=payload,
        signature=_signature(payload, key),
    )


def verify_execution_permit(
    permit: SignedExecutionPermit,
    engagement: Engagement,
    test: TestDefinition,
    request: PermitVerificationRequest,
    key: str | bytes | Mapping[str, str | bytes],
) -> PermitVerificationResult:
    checks: list[PermitCheck] = []

    if isinstance(key, Mapping):
        if permit.payload.key_id is None:
            if len(key) == 1:
                selected_key = next(iter(key.values()))
            else:
                checks.append(
                    PermitCheck(
                        name="key_id",
                        status=PermitCheckStatus.FAIL,
                        message="Legacy permit has no key_id and keyring is ambiguous.",
                    )
                )
                return PermitVerificationResult(valid=False, checks=checks)
        else:
            selected_key = key.get(permit.payload.key_id)
            if selected_key is None:
                checks.append(
                    PermitCheck(
                        name="key_id",
                        status=PermitCheckStatus.FAIL,
                        message=(
                            "No verification key is available for key_id "
                            f"{permit.payload.key_id!r}."
                        ),
                    )
                )
                return PermitVerificationResult(valid=False, checks=checks)
    else:
        selected_key = key

    expected_signature = _signature(permit.payload, selected_key)
    if not hmac.compare_digest(expected_signature, permit.signature):
        checks.append(
            PermitCheck(
                name="signature",
                status=PermitCheckStatus.FAIL,
                message="Permit signature is invalid.",
            )
        )
        return PermitVerificationResult(valid=False, checks=checks)
    checks.append(
        PermitCheck(
            name="signature",
            status=PermitCheckStatus.PASS,
            message="Permit signature is valid.",
        )
    )

    now = request.now or datetime.now(UTC)
    if now < permit.payload.issued_at or now >= permit.payload.expires_at:
        checks.append(
            PermitCheck(
                name="time_window",
                status=PermitCheckStatus.FAIL,
                message="Permit is not active at the requested time.",
            )
        )
        return PermitVerificationResult(valid=False, checks=checks)
    checks.append(
        PermitCheck(
            name="time_window",
            status=PermitCheckStatus.PASS,
            message="Permit is inside its validity window.",
        )
    )

    if permit.payload.engagement_id != engagement.id or permit.payload.test_id != test.id:
        checks.append(
            PermitCheck(
                name="binding",
                status=PermitCheckStatus.FAIL,
                message="Permit is bound to a different engagement or test.",
            )
        )
        return PermitVerificationResult(valid=False, checks=checks)

    if permit.payload.risk_class != test.risk_class:
        checks.append(
            PermitCheck(
                name="binding",
                status=PermitCheckStatus.FAIL,
                message="Permit risk class does not match the current test definition.",
            )
        )
        return PermitVerificationResult(valid=False, checks=checks)

    current_digest = policy_digest(engagement, test)
    if not hmac.compare_digest(permit.payload.policy_digest, current_digest):
        checks.append(
            PermitCheck(
                name="policy_digest",
                status=PermitCheckStatus.FAIL,
                message="Current policy or test definition differs from permit issuance.",
            )
        )
        return PermitVerificationResult(valid=False, checks=checks)
    checks.append(
        PermitCheck(
            name="policy_digest",
            status=PermitCheckStatus.PASS,
            message="Current policy matches the permit's policy digest.",
        )
    )

    method = request.http_method.upper() if request.http_method else None
    if (
        permit.payload.target != request.target
        or permit.payload.http_method != method
        or permit.payload.identity != request.identity
    ):
        checks.append(
            PermitCheck(
                name="action_binding",
                status=PermitCheckStatus.FAIL,
                message="Requested target, HTTP method, or identity differs from the permit.",
            )
        )
        return PermitVerificationResult(valid=False, checks=checks)
    checks.append(
        PermitCheck(
            name="action_binding",
            status=PermitCheckStatus.PASS,
            message="Requested action matches the permit binding.",
        )
    )

    requested_rate = request.requested_requests_per_second
    if requested_rate is not None and requested_rate > permit.payload.max_requests_per_second:
        checks.append(
            PermitCheck(
                name="rate_limit",
                status=PermitCheckStatus.FAIL,
                message=(
                    f"Requested rate {requested_rate:g} req/s exceeds permit limit "
                    f"{permit.payload.max_requests_per_second:g} req/s."
                ),
            )
        )
        return PermitVerificationResult(valid=False, checks=checks)
    checks.append(
        PermitCheck(
            name="rate_limit",
            status=PermitCheckStatus.PASS,
            message=(
                "Requested rate is within the permit's maximum of "
                f"{permit.payload.max_requests_per_second:g} req/s."
            ),
        )
    )

    return PermitVerificationResult(valid=True, checks=checks)
