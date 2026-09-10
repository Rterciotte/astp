from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class FieldCandidateRole(StrEnum):
    FRAMEWORK_RUNTIME = "framework_runtime"
    FRAMEWORK_LIBRARY = "framework_library"
    VENDOR_LIBRARY = "vendor_library"
    APPLICATION_BOOTSTRAP = "application_bootstrap"
    APPLICATION_CODE = "application_code"
    CONFIGURATION = "configuration"
    AUTH_ACCOUNT = "auth_account"
    STATIC_LOW_VALUE = "static_low_value"
    UNKNOWN = "unknown"


class FieldCandidateScope(StrEnum):
    SAME_ORIGIN = "same_origin"
    EXPLICIT_FIRST_PARTY = "explicit_first_party"
    THIRD_PARTY = "third_party"
    EXCLUDED = "excluded"
    SCOPE_REVIEW_REQUIRED = "scope_review_required"


class FieldCandidateFeatures(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    role: FieldCandidateRole
    scope_class: FieldCandidateScope
    independent_evidence_count: int = Field(default=1, ge=1)
    artifact_size_bytes: int | None = Field(default=None, ge=0)
    application_specific_terms: tuple[str, ...] = ()
    business_domain_terms: tuple[str, ...] = ()
    has_api_semantics: bool = False
    has_configuration_semantics: bool = False
    has_auth_account_semantics: bool = False
    has_application_route_semantics: bool = False
    source_map_tied_to_application: bool = False
    auth_or_state_involved: bool = False
    estimated_request_cost: int = Field(default=1, ge=1)


class RankedFieldCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    rank: int = Field(ge=1)
    target: str
    role: FieldCandidateRole
    scope_class: FieldCandidateScope
    application_semantic_score: int
    framework_penalty: int
    scope_penalty: int
    evidence_bonus: int
    final_score: int
    independent_evidence_count: int
    expected_information_gain: str
    estimated_request_cost: int
    operator_gate_required: bool = True
    semantic_policy_review_required: bool = False
    rationale: tuple[str, ...] = ()


_ROLE_SCORE = {
    FieldCandidateRole.FRAMEWORK_RUNTIME: 0,
    FieldCandidateRole.FRAMEWORK_LIBRARY: 0,
    FieldCandidateRole.VENDOR_LIBRARY: 0,
    FieldCandidateRole.APPLICATION_BOOTSTRAP: 45,
    FieldCandidateRole.APPLICATION_CODE: 38,
    FieldCandidateRole.CONFIGURATION: 46,
    FieldCandidateRole.AUTH_ACCOUNT: 40,
    FieldCandidateRole.STATIC_LOW_VALUE: 0,
    FieldCandidateRole.UNKNOWN: 8,
}

_FRAMEWORK_PENALTY = {
    FieldCandidateRole.FRAMEWORK_RUNTIME: 35,
    FieldCandidateRole.FRAMEWORK_LIBRARY: 30,
    FieldCandidateRole.VENDOR_LIBRARY: 25,
    FieldCandidateRole.STATIC_LOW_VALUE: 20,
}

_SCOPE_PENALTY = {
    FieldCandidateScope.SAME_ORIGIN: 0,
    FieldCandidateScope.EXPLICIT_FIRST_PARTY: 0,
    FieldCandidateScope.SCOPE_REVIEW_REQUIRED: 20,
    FieldCandidateScope.THIRD_PARTY: 35,
    FieldCandidateScope.EXCLUDED: 100,
}


def _semantic_score(candidate: FieldCandidateFeatures) -> tuple[int, tuple[str, ...]]:
    score = _ROLE_SCORE[candidate.role]
    reasons = [f"role={candidate.role.value}"]
    if candidate.application_specific_terms:
        contribution = min(len(set(candidate.application_specific_terms)) * 5, 20)
        score += contribution
        reasons.append(f"application-specific terms +{contribution}")
    if candidate.business_domain_terms:
        contribution = min(len(set(candidate.business_domain_terms)) * 6, 24)
        score += contribution
        reasons.append(f"business-domain terms +{contribution}")
    for enabled, contribution, label in (
        (candidate.has_api_semantics, 18, "API semantics"),
        (candidate.has_configuration_semantics, 18, "configuration semantics"),
        (candidate.has_auth_account_semantics, 25, "auth/account semantics"),
        (candidate.has_application_route_semantics, 10, "application route semantics"),
        (candidate.source_map_tied_to_application, 12, "application source map"),
    ):
        if enabled:
            score += contribution
            reasons.append(f"{label} +{contribution}")
    return score, tuple(reasons)


def rank_field_candidates(
    candidates: tuple[FieldCandidateFeatures, ...] | list[FieldCandidateFeatures],
) -> tuple[RankedFieldCandidate, ...]:
    """Rank persisted field candidates without network or size/centrality rewards."""
    scored: list[tuple[FieldCandidateFeatures, int, int, int, int, tuple[str, ...]]] = []
    for candidate in candidates:
        semantic_score, reasons = _semantic_score(candidate)
        framework_penalty = _FRAMEWORK_PENALTY.get(candidate.role, 0)
        scope_penalty = _SCOPE_PENALTY[candidate.scope_class]
        evidence_bonus = min(candidate.independent_evidence_count, 2) * 3
        final_score = semantic_score + evidence_bonus - framework_penalty - scope_penalty
        scored.append(
            (
                candidate,
                semantic_score,
                framework_penalty,
                scope_penalty,
                final_score,
                reasons,
            )
        )
    scored.sort(key=lambda row: (-row[4], row[0].target))
    results = []
    for rank, (
        candidate,
        semantic_score,
        framework_penalty,
        scope_penalty,
        final_score,
        reasons,
    ) in enumerate(scored, start=1):
        if final_score >= 75:
            gain = "high"
        elif final_score >= 40:
            gain = "medium"
        else:
            gain = "low"
        semantic_review = (
            candidate.scope_class is FieldCandidateScope.SCOPE_REVIEW_REQUIRED
            or candidate.has_auth_account_semantics
            or candidate.auth_or_state_involved
        )
        results.append(
            RankedFieldCandidate(
                rank=rank,
                target=candidate.target,
                role=candidate.role,
                scope_class=candidate.scope_class,
                application_semantic_score=semantic_score,
                framework_penalty=framework_penalty,
                scope_penalty=scope_penalty,
                evidence_bonus=min(candidate.independent_evidence_count, 2) * 3,
                final_score=final_score,
                independent_evidence_count=candidate.independent_evidence_count,
                expected_information_gain=gain,
                estimated_request_cost=candidate.estimated_request_cost,
                semantic_policy_review_required=semantic_review,
                rationale=reasons,
            )
        )
    return tuple(results)
