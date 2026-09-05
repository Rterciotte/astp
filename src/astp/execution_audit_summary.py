from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ExecutionAuditSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    network_actions: int = 0
    authenticated_actions: int = 0
    differential_pairs: int = 0
    verification_actions: int = 0
    browser_actions: int = 0
    external_adapter_actions: int = 0
    state_changing_actions: int = 0
    unresolved_errors: int = 0

    @property
    def total_actions(self) -> int:
        return (
            self.network_actions
            + self.authenticated_actions
            + self.verification_actions
            + self.browser_actions
            + self.external_adapter_actions
            + self.state_changing_actions
        )
