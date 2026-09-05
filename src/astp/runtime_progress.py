from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_execution_gate import evaluate_runtime_execution_gate
from astp.runtime_qualification_record import RuntimeQualificationRecord
from astp.runtime_specs import builtin_runtime_specs


class RuntimeProgress(BaseModel):
    model_config = ConfigDict(frozen=True)

    qualified_runtimes: int
    total_runtimes: int
    operational_runtime_ids: tuple[str, ...] = Field(default_factory=tuple)
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def current_runtime_progress(
    records: tuple[RuntimeQualificationRecord, ...] = (),
) -> RuntimeProgress:
    specs = builtin_runtime_specs()
    ready: list[str] = []
    blockers: list[str] = []
    for spec in specs:
        result = evaluate_runtime_execution_gate(spec.id, records)
        if result.allowed:
            ready.append(spec.id)
        else:
            blockers.extend(f"{spec.id}: {item}" for item in result.blockers)
    return RuntimeProgress(
        qualified_runtimes=len(ready),
        total_runtimes=len(specs),
        operational_runtime_ids=tuple(ready),
        blockers=tuple(blockers),
    )
