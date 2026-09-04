import pytest

from astp.models import RiskClass
from astp.test_dsl import ExecutionStrategy, SecurityTestDefinition


def test_dsl_converts_to_existing_runtime_definition() -> None:
    definition = SecurityTestDefinition(
        id="observation.http",
        title="HTTP observation",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
        preconditions=["program_online"],
        execution_strategy=ExecutionStrategy.OBSERVE_HTTP,
        evidence={"required": ["response_metadata"]},
    )
    runtime = definition.to_runtime_test()
    assert runtime.id == definition.id
    assert runtime.required_context == ["program_online"]


def test_observe_http_strategy_cannot_claim_intrusive_risk() -> None:
    with pytest.raises(ValueError):
        SecurityTestDefinition(
            id="bad",
            title="bad",
            category="bad",
            risk_class=RiskClass.INTRUSIVE,
            execution_strategy=ExecutionStrategy.OBSERVE_HTTP,
        )
