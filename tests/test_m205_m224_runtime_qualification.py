from __future__ import annotations

from datetime import UTC, datetime

from astp.completion_readiness import evaluate_completion_readiness
from astp.coordinator import CoordinatorStage
from astp.coordinator_execution import build_execution_ticket, evaluate_ticket_budget
from astp.coordinator_feedback import ReplanDecision, evaluate_feedback
from astp.evidence_gate import EvidenceAcceptanceContext, evaluate_evidence_acceptance
from astp.execution_budget import StageExecutionBudget, evaluate_stage_budget
from astp.recovery_checkpoint import build_recovery_checkpoint
from astp.runtime_qualification import (
    RuntimeQualificationEvidence,
    qualification_template,
    qualify_runtime,
)
from astp.runtime_specs import builtin_runtime_specs
from astp.verifier_readiness import current_verifier_family_readiness


def _qualified(runtime_id: str) -> RuntimeQualificationEvidence:
    return RuntimeQualificationEvidence(
        runtime_id=runtime_id,
        artifact_digest="sha256:abc",
        version_reported="1.0.0",
        permit_consumed_before_io_tested=True,
        network_without_permit_rejected=True,
        arbitrary_shell_rejected=True,
        signing_keys_absent=True,
        output_bound_tested=True,
        field_test_name="authorized-lab",
    )


def test_m205_runtime_specs_are_pinned_contracts_not_readiness_claims():
    specs = builtin_runtime_specs()
    assert len(specs) == 2
    assert all(spec.network_requires_permit for spec in specs)
    assert all(spec.shell_allowed is False for spec in specs)


def test_m206_qualification_template_is_unqualified():
    spec = builtin_runtime_specs()[0]
    result = qualify_runtime(spec, qualification_template(spec.id))
    assert result.qualified is False
    assert result.blockers


def test_m207_complete_runtime_evidence_can_qualify_exact_runtime():
    spec = builtin_runtime_specs()[0]
    result = qualify_runtime(spec, _qualified(spec.id))
    assert result.qualified is True


def test_m208_runtime_evidence_is_exact_id_bound():
    spec = builtin_runtime_specs()[0]
    evidence = _qualified(builtin_runtime_specs()[1].id)
    assert qualify_runtime(spec, evidence).qualified is False


def test_m209_stage_budget_allows_bounded_action():
    budget = StageExecutionBudget(stage=CoordinatorStage.OBSERVATION, max_network_actions=2)
    assert evaluate_stage_budget(budget, network_actions=1, errors=0, elapsed_seconds=1).allowed


def test_m210_stage_budget_stops_at_action_ceiling():
    budget = StageExecutionBudget(stage=CoordinatorStage.OBSERVATION, max_network_actions=2)
    assert not evaluate_stage_budget(budget, network_actions=2, errors=0, elapsed_seconds=1).allowed


def test_m211_stage_budget_rejects_state_change_by_default():
    budget = StageExecutionBudget(stage=CoordinatorStage.VERIFICATION)
    result = evaluate_stage_budget(
        budget,
        network_actions=0,
        errors=0,
        elapsed_seconds=0,
        state_changing=True,
    )
    assert result.allowed is False


def test_m212_evidence_gate_accepts_verified_bound_evidence():
    result = evaluate_evidence_acceptance(
        EvidenceAcceptanceContext(
            evidence_id="ev-1",
            manifest_verified=True,
            action_id_matches=True,
            engagement_id_matches=True,
        )
    )
    assert result.accepted is True


def test_m213_evidence_gate_rejects_quarantine():
    result = evaluate_evidence_acceptance(
        EvidenceAcceptanceContext(
            evidence_id="ev-1",
            manifest_verified=True,
            action_id_matches=True,
            engagement_id_matches=True,
            quarantined=True,
        )
    )
    assert result.accepted is False


def test_m214_active_verifier_families_are_not_overclaimed_operational():
    rows = current_verifier_family_readiness()
    assert rows
    assert any(row.active_definitions > 0 and not row.operationally_qualified for row in rows)


def test_m215_coordinator_ticket_is_planning_only():
    ticket = build_execution_ticket("eng-1", CoordinatorStage.OBSERVATION, ("a1", "a1", "a2"))
    assert ticket.action_ids == ("a1", "a2")
    assert ticket.execution_enabled is False
    assert ticket.fresh_permit_per_action is True


def test_m216_ticket_budget_requires_matching_stage():
    ticket = build_execution_ticket("eng-1", CoordinatorStage.OBSERVATION, ("a1",))
    budget = StageExecutionBudget(stage=CoordinatorStage.VERIFICATION)
    result = evaluate_ticket_budget(ticket, budget, network_actions=0, errors=0, elapsed_seconds=0)
    assert result.allowed is False


def test_m217_feedback_replans_when_new_signals_exist():
    result = evaluate_feedback(
        accepted_evidence=1,
        rejected_evidence=0,
        new_signals=1,
        new_verification_proposals=0,
        errors=0,
    )
    assert result.decision is ReplanDecision.REPLAN


def test_m218_feedback_stops_on_error_budget():
    result = evaluate_feedback(
        accepted_evidence=0,
        rejected_evidence=0,
        new_signals=0,
        new_verification_proposals=0,
        errors=3,
    )
    assert result.decision is ReplanDecision.STOP


def test_m219_recovery_checkpoint_hash_is_deterministic_for_same_inputs():
    now = datetime(2026, 9, 5, tzinfo=UTC)
    first = build_recovery_checkpoint("eng-1", CoordinatorStage.OBSERVATION, "policy", now=now)
    second = build_recovery_checkpoint("eng-1", CoordinatorStage.OBSERVATION, "policy", now=now)
    assert first.checkpoint_hash == second.checkpoint_hash


def test_m220_recovery_checkpoint_binds_policy_digest():
    now = datetime(2026, 9, 5, tzinfo=UTC)
    first = build_recovery_checkpoint("eng-1", CoordinatorStage.OBSERVATION, "p1", now=now)
    second = build_recovery_checkpoint("eng-1", CoordinatorStage.OBSERVATION, "p2", now=now)
    assert first.checkpoint_hash != second.checkpoint_hash


def test_m221_completion_gate_remains_false_without_runtime_qualification():
    specs = builtin_runtime_specs()
    results = tuple(qualify_runtime(spec, qualification_template(spec.id)) for spec in specs)
    completion = evaluate_completion_readiness(results, current_verifier_family_readiness())
    assert completion.full_runtime_ready is False
    assert completion.full_pentest_ready is False


def test_m222_even_qualified_runtimes_do_not_bypass_verifier_or_operator_gates():
    specs = builtin_runtime_specs()
    results = tuple(qualify_runtime(spec, _qualified(spec.id)) for spec in specs)
    completion = evaluate_completion_readiness(results, current_verifier_family_readiness())
    assert completion.full_runtime_ready is True
    assert completion.full_pentest_ready is False


def test_m223_runtime_qualification_requires_field_test_name():
    spec = builtin_runtime_specs()[0]
    evidence = _qualified(spec.id).model_copy(update={"field_test_name": None})
    result = qualify_runtime(spec, evidence)
    assert result.qualified is False
    assert "field test recorded" in result.blockers


def test_m224_state_change_operator_path_is_explicit_completion_gate():
    specs = builtin_runtime_specs()
    results = tuple(qualify_runtime(spec, _qualified(spec.id)) for spec in specs)
    completion = evaluate_completion_readiness(
        results,
        current_verifier_family_readiness(),
        state_changing_operator_path_field_tested=False,
    )
    assert any("state-changing" in blocker for blocker in completion.blockers)
