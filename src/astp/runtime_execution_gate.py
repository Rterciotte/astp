from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_qualification_record import RuntimeQualificationRecord


class RuntimeExecutionGate(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    allowed: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def evaluate_runtime_execution_gate(
    runtime_id: str,
    records: tuple[RuntimeQualificationRecord, ...],
) -> RuntimeExecutionGate:
    matches = [item for item in records if item.runtime_id == runtime_id]
    if not matches:
        return RuntimeExecutionGate(
            runtime_id=runtime_id,
            allowed=False,
            blockers=("runtime has no qualification record",),
        )
    record = matches[-1]
    if not record.qualified:
        return RuntimeExecutionGate(
            runtime_id=runtime_id,
            allowed=False,
            blockers=("runtime qualification is incomplete",),
        )
    if not record.field_test_name:
        return RuntimeExecutionGate(
            runtime_id=runtime_id,
            allowed=False,
            blockers=("runtime has not been field-tested",),
        )
    return RuntimeExecutionGate(runtime_id=runtime_id, allowed=True)
