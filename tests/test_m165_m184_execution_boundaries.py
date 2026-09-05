from pathlib import Path

import pytest

from astp.assessment_capabilities import current_capability_matrix
from astp.assessment_coverage import current_assessment_coverage
from astp.browser_runtime import BrowserObservation
from astp.browser_worker import BrowserWorkerJob, execute_permit_consumed_browser
from astp.coordinator import CoordinatorStage, build_coordinator_plan
from astp.coordinator_state import set_coordinator_stage
from astp.external_adapter_runtime import build_external_adapter_job
from astp.pentest_readiness import current_pentest_readiness
from astp.permit_consumed_adapter import execute_permit_consumed_adapter
from astp.proof_requirements import builtin_proof_requirements
from astp.runtime_isolation import default_runtime_isolation_policy
from astp.tool_output_guard import bound_tool_output
from astp.verifier_catalog import builtin_verifier_catalog


def test_adapter_consumes_before_runner():
    events = []
    job = build_external_adapter_job(
        "nmap.safe-discovery.v1",
        "example.com",
        "tcp-connect-bounded",
        permit_id="p1",
        action_id="a1",
    )

    def consume(p, a):
        events.append(("consume", p, a))

    def runner(_):
        events.append(("run",))
        return 0, b"ok", b""

    receipt = execute_permit_consumed_adapter(job, consume=consume, runner=runner)
    assert receipt.execution_performed is True
    assert events[0][0] == "consume"


def test_browser_consumes_before_driver():
    events = []
    job = BrowserWorkerJob(id="b1", target="https://example.com/", permit_id="p", action_id="a")

    def consume(p, a):
        events.append("consume")

    def driver(target):
        events.append("driver")
        return BrowserObservation(target=target, final_url=target)

    execute_permit_consumed_browser(job, consume=consume, driver=driver)
    assert events == ["consume", "driver"]


def test_browser_redirect_requires_reauthorization():
    job = BrowserWorkerJob(id="b1", target="https://example.com/", permit_id="p", action_id="a")
    with pytest.raises(ValueError, match="redirect"):
        execute_permit_consumed_browser(
            job,
            consume=lambda *_: None,
            driver=lambda target: BrowserObservation(
                target=target, final_url="https://www.example.com/", redirect_observed=True
            ),
        )


def test_verifier_catalog_is_non_state_changing():
    catalog = builtin_verifier_catalog()
    assert len(catalog) >= 6
    assert all(not item.state_changing for item in catalog)


def test_proof_requirements_keep_verified_manual():
    assert all(not item.automatic_verified_allowed for item in builtin_proof_requirements())


def test_runtime_isolation_has_no_keys_or_shell():
    policy = default_runtime_isolation_policy()
    assert not policy.signing_keys_available
    assert not policy.subprocess_shell_allowed
    assert policy.permit_required_for_network


def test_output_guard_truncates():
    data, result = bound_tool_output(b"abcdef", 3)
    assert data == b"abc"
    assert result.truncated


def test_coordinator_defaults_to_no_network():
    plan = build_coordinator_plan("eng-1")
    assert plan.stages[-1] == CoordinatorStage.CLOSURE
    assert not plan.network_execution_enabled
    assert not plan.state_changing_autonomy


def test_coordinator_state_persists(tmp_path: Path):
    db = tmp_path / "state.db"
    set_coordinator_stage(db, "eng-1", CoordinatorStage.OBSERVATION)
    assert db.exists()


def test_capability_matrix_closes_safe_worker_gaps():
    matrix = current_capability_matrix()
    assert matrix.browser_observation_worker
    assert matrix.permit_consumed_external_adapters
    assert not matrix.autonomous_state_change


def test_worker_boundaries_do_not_prematurely_close_operational_coverage():
    coverage = current_assessment_coverage()
    assert coverage.completed_dimensions == 9
    assert coverage.total_dimensions == 11
    assert not coverage.browser_dynamic
    assert not coverage.external_adapters


def test_readiness_still_not_full():
    readiness = current_pentest_readiness()
    assert not readiness.browser_execution_worker
    assert not readiness.external_tool_adapters
    assert not readiness.full_pentest_ready
    assert readiness.blockers
