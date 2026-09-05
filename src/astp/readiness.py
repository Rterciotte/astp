from __future__ import annotations

from pydantic import BaseModel, Field


class ReadinessCheck(BaseModel):
    name: str
    ready: bool
    detail: str


class AssessmentReadiness(BaseModel):
    schema_version: str = "1"
    ready: bool
    checks: list[ReadinessCheck] = Field(default_factory=list)


def evaluate_assessment_readiness(
    *,
    policy_ready: bool,
    attestation_fresh: bool,
    permit_keys_configured: bool,
    evidence_store_ready: bool,
    worker_contracts_ready: bool,
) -> AssessmentReadiness:
    values = {
        "policy": policy_ready,
        "operational_attestation": attestation_fresh,
        "permit_keys": permit_keys_configured,
        "evidence_store": evidence_store_ready,
        "worker_contracts": worker_contracts_ready,
    }
    checks = [
        ReadinessCheck(
            name=name,
            ready=value,
            detail="ready" if value else "blocking prerequisite missing",
        )
        for name, value in values.items()
    ]
    return AssessmentReadiness(ready=all(values.values()), checks=checks)
