from __future__ import annotations

import hashlib
import socket

from astp.field_candidate_ranking import (
    FieldCandidateFeatures,
    FieldCandidateRole,
    FieldCandidateScope,
    rank_field_candidates,
)
from astp.secret_exposure import SecretKind, analyze_exposed_content, secret_signal_identity

TOKEN_A = "abcdefghijklmnopqrstuvwxyz012345"
TOKEN_B = "ABCDEFGHIJKLMNOPQRSTUVWXYZ987654"


def _candidate(
    target: str,
    role: FieldCandidateRole,
    **updates: object,
) -> FieldCandidateFeatures:
    return FieldCandidateFeatures(
        target=target,
        role=role,
        scope_class=FieldCandidateScope.SAME_ORIGIN,
        **updates,
    )


def test_duplicate_entropy_emission_is_suppressed_at_source() -> None:
    signals = analyze_exposed_content(f"{TOKEN_A} {TOKEN_A}".encode())
    entropy = [signal for signal in signals if signal.kind is SecretKind.HIGH_ENTROPY]
    assert len(entropy) == 1


def test_genuinely_distinct_entropy_matches_remain_distinguishable() -> None:
    signals = analyze_exposed_content(f"{TOKEN_A} {TOKEN_B}".encode())
    entropy = [signal for signal in signals if signal.kind is SecretKind.HIGH_ENTROPY]
    assert len(entropy) == 2
    assert len({signal.value_sha256 for signal in entropy}) == 2


def test_redacted_hash_identity_is_deterministic_and_private() -> None:
    first = analyze_exposed_content(TOKEN_A.encode())[0]
    second = analyze_exposed_content(TOKEN_A.encode())[0]
    expected_hash = hashlib.sha256(TOKEN_A.encode()).hexdigest()
    assert first.redacted_value == second.redacted_value == "abcd…2345"
    assert first.value_sha256 == second.value_sha256 == expected_hash
    assert TOKEN_A not in first.model_dump_json()
    assert secret_signal_identity(
        first.kind,
        first.value_sha256,
        context_class="TEXT/PLAIN",
    ) == secret_signal_identity(
        second.kind,
        second.value_sha256,
        context_class="text/plain",
    )


def test_framework_runtime_receives_penalty() -> None:
    ranked = rank_field_candidates(
        [_candidate("https://example.test/runtime.js", FieldCandidateRole.FRAMEWORK_RUNTIME)]
    )[0]
    assert ranked.framework_penalty == 35
    assert ranked.final_score < 0


def test_application_specific_artifact_outranks_generic_runtime() -> None:
    ranked = rank_field_candidates(
        [
            _candidate("https://example.test/runtime.js", FieldCandidateRole.FRAMEWORK_RUNTIME),
            _candidate(
                "https://example.test/subscription.js",
                FieldCandidateRole.APPLICATION_CODE,
                application_specific_terms=("smart-fit",),
                business_domain_terms=("subscription", "payment"),
                has_api_semantics=True,
            ),
        ]
    )
    assert ranked[0].target.endswith("subscription.js")


def test_artifact_size_alone_does_not_increase_rank() -> None:
    small = _candidate(
        "https://example.test/a.js",
        FieldCandidateRole.UNKNOWN,
        artifact_size_bytes=1,
    )
    large = _candidate(
        "https://example.test/b.js",
        FieldCandidateRole.UNKNOWN,
        artifact_size_bytes=10_000_000,
    )
    scores = {row.target: row.final_score for row in rank_field_candidates([small, large])}
    assert scores[small.target] == scores[large.target]


def test_reference_count_is_capped_and_does_not_dominate() -> None:
    one = _candidate(
        "https://example.test/a.js",
        FieldCandidateRole.UNKNOWN,
        independent_evidence_count=1,
    )
    many = _candidate(
        "https://example.test/b.js",
        FieldCandidateRole.UNKNOWN,
        independent_evidence_count=100,
    )
    scores = {row.target: row.final_score for row in rank_field_candidates([one, many])}
    assert scores[many.target] - scores[one.target] == 3


def test_auth_login_candidate_requires_semantic_policy_review() -> None:
    ranked = rank_field_candidates(
        [
            FieldCandidateFeatures(
                target="https://account.example.test/login",
                role=FieldCandidateRole.AUTH_ACCOUNT,
                scope_class=FieldCandidateScope.EXPLICIT_FIRST_PARTY,
                has_auth_account_semantics=True,
                auth_or_state_involved=True,
            )
        ]
    )[0]
    assert ranked.operator_gate_required
    assert ranked.semantic_policy_review_required


def test_reranking_is_deterministic() -> None:
    candidates = [
        _candidate("https://example.test/b.js", FieldCandidateRole.UNKNOWN),
        _candidate("https://example.test/a.js", FieldCandidateRole.UNKNOWN),
    ]
    first = rank_field_candidates(candidates)
    second = rank_field_candidates(list(reversed(candidates)))
    assert first == second
    assert [row.target for row in first] == sorted(row.target for row in first)


def test_ranking_performs_no_network(monkeypatch) -> None:
    def fail_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "create_connection", fail_network)
    result = rank_field_candidates(
        [_candidate("https://example.test/app.js", FieldCandidateRole.APPLICATION_CODE)]
    )
    assert len(result) == 1
