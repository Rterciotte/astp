from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ExternalAdapterContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    executable: str
    capability_id: str
    permit_required: bool = True
    arbitrary_arguments_allowed: bool = False
    state_changing_allowed: bool = False
    network_without_permit_allowed: bool = False
    runtime_ready: bool = False
    allowed_modes: tuple[str, ...]


def builtin_external_adapter_contracts() -> tuple[ExternalAdapterContract, ...]:
    return (
        ExternalAdapterContract(
            id="nmap.safe-discovery.v1",
            executable="nmap",
            capability_id="external.nmap.discovery.v1",
            allowed_modes=("tcp-connect-bounded", "service-detection-bounded"),
        ),
        ExternalAdapterContract(
            id="nuclei.safe-templates.v1",
            executable="nuclei",
            capability_id="external.nuclei.safe.v1",
            allowed_modes=("info", "low-impact"),
        ),
        ExternalAdapterContract(
            id="zap.baseline.v1",
            executable="zap-baseline",
            capability_id="external.zap.baseline.v1",
            allowed_modes=("passive-baseline",),
        ),
    )
