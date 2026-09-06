from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from astp.models import Engagement, OperationalStatus, ProgramOperationalAttestation

MAX_ASSESSMENT_LEASE_SECONDS = 1800


class ProgramOperationalLease(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    id: str
    program_id: str
    source_content_sha256: str
    attestation_id: str
    attestation_observed_at: datetime
    status: OperationalStatus
    assessment_id: str
    preflight_report_hash: str
    valid_from: datetime
    valid_until: datetime
    lease_hash: str

    @field_validator("attestation_observed_at", "valid_from", "valid_until")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("operational lease timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> ProgramOperationalLease:
        if self.valid_until <= self.valid_from:
            raise ValueError("operational lease valid_until must be after valid_from")
        return self


def _canonical_hash(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_operational_lease(
    engagement: Engagement,
    attestation: ProgramOperationalAttestation,
    *,
    assessment_id: str,
    preflight_report_hash: str,
    valid_from: datetime,
    ttl_seconds: int = MAX_ASSESSMENT_LEASE_SECONDS,
) -> ProgramOperationalLease:
    binding = engagement.program
    if binding is None or not binding.requires_online:
        raise ValueError("engagement does not require an operational program gate")
    if ttl_seconds < 30 or ttl_seconds > MAX_ASSESSMENT_LEASE_SECONDS:
        raise ValueError(
            f"assessment operational lease TTL must be between 30 and {MAX_ASSESSMENT_LEASE_SECONDS} seconds"
        )
    if attestation.status != OperationalStatus.ONLINE:
        raise ValueError("assessment operational lease requires an ONLINE attestation")
    if (
        attestation.program_id != binding.program_id
        or attestation.source_content_sha256 != binding.source_content_sha256
    ):
        raise ValueError("attestation is bound to a different program revision")
    if valid_from.tzinfo is None or valid_from.utcoffset() is None:
        raise ValueError("lease valid_from must include a timezone")
    fresh_until = attestation.observed_at + timedelta(
        seconds=binding.operational_attestation_max_age_seconds
    )
    if valid_from < attestation.observed_at - timedelta(seconds=30) or valid_from >= fresh_until:
        raise ValueError("operational lease can only originate while the attestation is fresh")
    payload: dict[str, object] = {
        "schema_version": "1",
        "program_id": binding.program_id,
        "source_content_sha256": binding.source_content_sha256,
        "attestation_id": attestation.id,
        "attestation_observed_at": attestation.observed_at.isoformat(),
        "status": OperationalStatus.ONLINE.value,
        "assessment_id": assessment_id,
        "preflight_report_hash": preflight_report_hash,
        "valid_from": valid_from.isoformat(),
        "valid_until": (valid_from + timedelta(seconds=ttl_seconds)).isoformat(),
    }
    digest = _canonical_hash(payload)
    payload["id"] = f"oplease-{digest[:12]}"
    payload["lease_hash"] = digest
    return ProgramOperationalLease.model_validate(payload)


def lease_is_valid(
    lease: ProgramOperationalLease,
    engagement: Engagement,
    attestation: ProgramOperationalAttestation,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    binding = engagement.program
    current = now or datetime.now(UTC)
    if binding is None or not binding.requires_online:
        return False, "engagement does not require an operational program gate"
    if lease.status != OperationalStatus.ONLINE or attestation.status != OperationalStatus.ONLINE:
        return False, "lease and source attestation must both be ONLINE"
    if lease.attestation_id != attestation.id:
        return False, "operational lease is bound to a different attestation"
    if (
        lease.program_id != binding.program_id
        or lease.source_content_sha256 != binding.source_content_sha256
        or attestation.program_id != binding.program_id
        or attestation.source_content_sha256 != binding.source_content_sha256
    ):
        return False, "operational lease is bound to a different program revision"
    if lease.attestation_observed_at != attestation.observed_at:
        return False, "operational lease attestation timestamp binding does not match"
    if current < lease.valid_from - timedelta(seconds=30):
        return False, "operational lease is not active yet"
    if current >= lease.valid_until:
        return False, "operational lease is stale and must be refreshed"
    payload = {
        "schema_version": lease.schema_version,
        "program_id": lease.program_id,
        "source_content_sha256": lease.source_content_sha256,
        "attestation_id": lease.attestation_id,
        "attestation_observed_at": lease.attestation_observed_at.isoformat(),
        "status": lease.status.value,
        "assessment_id": lease.assessment_id,
        "preflight_report_hash": lease.preflight_report_hash,
        "valid_from": lease.valid_from.isoformat(),
        "valid_until": lease.valid_until.isoformat(),
    }
    expected = _canonical_hash(payload)
    if lease.lease_hash != expected or lease.id != f"oplease-{expected[:12]}":
        return False, "operational lease integrity check failed"
    return True, "bounded assessment operational lease is valid"
