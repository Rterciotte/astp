from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict


class AuthorizationDifferentialPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    target: str
    baseline_identity: str
    comparison_identity: str
    method: str = "GET"
    requires_distinct_owned_identities: bool = True
    fresh_permit_per_request: bool = True
    state_changing: bool = False
    execution_performed: bool = False


def build_authorization_differential_plan(
    target: str,
    baseline_identity: str,
    comparison_identity: str,
) -> AuthorizationDifferentialPlan:
    if not baseline_identity.strip() or not comparison_identity.strip():
        raise ValueError("two explicit identities are required")
    if baseline_identity == comparison_identity:
        raise ValueError("differential verification requires distinct identities")
    digest = hashlib.sha256(
        f"{target}|{baseline_identity}|{comparison_identity}".encode()
    ).hexdigest()[:16]
    return AuthorizationDifferentialPlan(
        id=f"authz-diff-{digest}",
        target=target,
        baseline_identity=baseline_identity,
        comparison_identity=comparison_identity,
    )
