from __future__ import annotations

import hashlib
import re

from pydantic import BaseModel, Field

from astp.proof_model import ProofStateV2


class IdentityObservation(BaseModel):
    identity_ref: str
    status_code: int
    content_type: str | None = None
    body: str = ""
    action_succeeded: bool | None = None
    expected_owner: bool | None = None


class DifferentialAccessResult(BaseModel):
    state: ProofStateV2
    materially_equivalent: bool
    sensitive_fields_exposed: tuple[str, ...] = ()
    identity_hashes: tuple[str, ...]
    reason: str
    confidence: float = Field(ge=0, le=1)


_SENSITIVE = re.compile(r'(?i)["\'](email|phone|address|ssn|cpf|token|secret)["\']\s*:')


def _normalized(body: str) -> str:
    return re.sub(r"\b\d+\b", "#", re.sub(r"\s+", " ", body)).strip()


def compare_identity_observations(
    a: IdentityObservation, b: IdentityObservation
) -> DifferentialAccessResult:
    hashes = tuple(hashlib.sha256(row.identity_ref.encode()).hexdigest()[:12] for row in (a, b))
    equivalent = (a.status_code, a.content_type, _normalized(a.body)) == (
        b.status_code,
        b.content_type,
        _normalized(b.body),
    )
    fields = tuple(sorted(set(_SENSITIVE.findall(a.body + b.body))))
    unauthorized = (
        a.expected_owner is False and a.status_code < 400 and (fields or a.action_succeeded)
    ) or (b.expected_owner is False and b.status_code < 400 and (fields or b.action_succeeded))
    if unauthorized:
        return DifferentialAccessResult(
            state=ProofStateV2.CONFIRMED,
            materially_equivalent=equivalent,
            sensitive_fields_exposed=fields,
            identity_hashes=hashes,
            reason="non-owner observation exposed a sensitive object/action",
            confidence=0.95,
        )
    return DifferentialAccessResult(
        state=ProofStateV2.CANDIDATE if not equivalent else ProofStateV2.OBSERVED,
        materially_equivalent=equivalent,
        sensitive_fields_exposed=fields,
        identity_hashes=hashes,
        reason="response difference alone does not prove unauthorized access",
        confidence=0.45 if not equivalent else 0.2,
    )
