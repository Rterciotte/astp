from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class RuntimeIsolationPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)
    signing_keys_available: bool = False
    arbitrary_mounts_allowed: bool = False
    arbitrary_network_allowed: bool = False
    secret_export_allowed: bool = False
    subprocess_shell_allowed: bool = False
    permit_required_for_network: bool = True


def default_runtime_isolation_policy() -> RuntimeIsolationPolicy:
    return RuntimeIsolationPolicy()
