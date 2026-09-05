from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class WorkerIsolationContract(BaseModel):
    adapter_id: str
    container_image: str
    network_enabled: bool = False
    read_only_root: bool = True
    run_as_non_root: bool = True
    allow_host_paths: list[str] = Field(default_factory=list)
    receives_signing_key: bool = False
    requires_execution_permit: bool = True

    @model_validator(mode="after")
    def enforce_boundary(self) -> WorkerIsolationContract:
        if not self.read_only_root or not self.run_as_non_root:
            raise ValueError("isolated workers require read-only root and non-root execution")
        if self.allow_host_paths:
            raise ValueError("isolated workers may not mount arbitrary host paths")
        if self.receives_signing_key:
            raise ValueError("workers may verify permits but never receive signing keys")
        if self.network_enabled and not self.requires_execution_permit:
            raise ValueError("network workers must require execution permits")
        return self
