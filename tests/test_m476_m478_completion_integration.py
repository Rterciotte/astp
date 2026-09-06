from __future__ import annotations

from inspect import signature
from pathlib import Path

from typer.testing import CliRunner

from astp.active_verifier_registry import ActiveVerifierRisk
from astp.authenticated_observation import observe_authenticated_http
from astp.cli import app
from astp.portfolio_orchestrator import build_portfolio_plan
from astp.program_models import (
    BugBountyProgram,
    ProgramOperationalStatus,
    ProgramSourceSnapshot,
    ProgramVisibility,
)
from astp.verification_workflow import plan_verification_workflow

runner = CliRunner()


def _program(program_id: str) -> BugBountyProgram:
    return BugBountyProgram(
        id=program_id,
        name=program_id,
        platform="test",
        visibility=ProgramVisibility.PUBLIC,
        operational_status=ProgramOperationalStatus.ONLINE,
        source=ProgramSourceSnapshot(source_type="test", content_sha256="a" * 64),
    )


def test_m476_portfolio_keeps_program_namespaces_independent():
    plan = build_portfolio_plan([_program("beta"), _program("alpha")])
    assert plan.fair_queue_order == ("alpha", "beta")
    assert plan.programs[0].evidence_namespace != plan.programs[1].evidence_namespace
    assert plan.independent_policy_and_evidence is True
    assert plan.execution_enabled is False


def test_m476_portfolio_rejects_duplicate_program_ids():
    import pytest

    with pytest.raises(ValueError, match="duplicate"):
        build_portfolio_plan([_program("same"), _program("same")])


def test_m477_authenticated_observation_supports_bounded_body_controls():
    params = signature(observe_authenticated_http).parameters
    assert "persist_body" in params
    assert "max_body_bytes" in params
    assert "timeout_seconds" in params


def test_m477_authenticated_cli_is_exposed_without_raw_secret_argument():
    result = runner.invoke(app, ["observe-authenticated-http", "--help"])
    assert result.exit_code == 0
    assert "AuthSessionProfile" in result.stdout
    assert "--persist-body" in result.stdout
    assert "password" not in result.stdout.lower()


def test_m478_verification_workflow_is_non_executing_and_state_change_gated(tmp_path: Path):
    workflow = plan_verification_workflow(tmp_path)
    assert workflow.network_performed is False
    assert workflow.execution_enabled is False
    assert workflow.batch.execution_enabled is False
    assert workflow.batch.fresh_permit_per_action is True
    assert any(item.risk is ActiveVerifierRisk.STATE_CHANGING for item in workflow.active_verifiers)
    assert workflow.state_changing_verifiers


def test_m478_verification_cli_is_planning_only():
    result = runner.invoke(app, ["plan-verification", "--help"])
    assert result.exit_code == 0
    assert "never execute" in result.stdout.lower()
