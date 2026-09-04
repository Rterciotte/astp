from __future__ import annotations

from pydantic import BaseModel, Field

from astp.models import RiskClass
from astp.test_dsl import ExecutionStrategy, SecurityTestDefinition


class AdapterDescriptor(BaseModel):
    id: str
    version: str
    strategies: set[ExecutionStrategy] = Field(default_factory=set)
    risk_classes: set[RiskClass] = Field(default_factory=set)
    network_capable: bool = False
    state_changing: bool = False
    requires_execution_permit: bool = True


class AdapterRegistry(BaseModel):
    schema_version: str = "1"
    adapters: list[AdapterDescriptor] = Field(default_factory=list)

    def get(self, adapter_id: str) -> AdapterDescriptor:
        for adapter in self.adapters:
            if adapter.id == adapter_id:
                return adapter
        raise ValueError(f"unknown adapter: {adapter_id}")


def builtin_adapter_registry() -> AdapterRegistry:
    return AdapterRegistry(
        adapters=[
            AdapterDescriptor(
                id="http.observation.v1",
                version="1",
                strategies={ExecutionStrategy.OBSERVE_HTTP},
                risk_classes={RiskClass.PASSIVE, RiskClass.SAFE_ACTIVE},
                network_capable=True,
                state_changing=False,
                requires_execution_permit=True,
            )
        ]
    )


def ensure_adapter_compatible(
    adapter: AdapterDescriptor,
    definition: SecurityTestDefinition,
) -> None:
    if definition.execution_strategy not in adapter.strategies:
        raise ValueError("adapter does not support this DSL execution strategy")
    if definition.risk_class not in adapter.risk_classes:
        raise ValueError("adapter does not support this DSL risk class")
    if adapter.network_capable and not adapter.requires_execution_permit:
        raise ValueError("network-capable ASTP adapters must require execution permits")
    if definition.execution_strategy == ExecutionStrategy.OBSERVE_HTTP and adapter.state_changing:
        raise ValueError("observation adapter may not be state changing")
