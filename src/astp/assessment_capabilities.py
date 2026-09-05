from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AssessmentCapabilityMatrix(BaseModel):
    model_config = ConfigDict(frozen=True)
    safe_http: bool = True
    authenticated_http: bool = True
    dns_tls: bool = True
    authorization_differential: bool = True
    safe_active_verification: bool = True
    browser_observation_worker: bool = True
    permit_consumed_external_adapters: bool = True
    broad_verifier_catalog: bool = True
    autonomous_state_change: bool = False


def current_capability_matrix() -> AssessmentCapabilityMatrix:
    return AssessmentCapabilityMatrix()
