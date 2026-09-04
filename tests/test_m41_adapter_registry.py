from astp.adapter_registry import builtin_adapter_registry, ensure_adapter_compatible
from astp.models import RiskClass
from astp.test_dsl import ExecutionStrategy, SecurityTestDefinition


def test_builtin_http_adapter_requires_permit():
    adapter = builtin_adapter_registry().get("http.observation.v1")
    assert adapter.network_capable
    assert adapter.requires_execution_permit
    definition = SecurityTestDefinition(
        id="x",
        title="x",
        category="obs",
        risk_class=RiskClass.SAFE_ACTIVE,
        execution_strategy=ExecutionStrategy.OBSERVE_HTTP,
    )
    ensure_adapter_compatible(adapter, definition)
