from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from astp.approval_workflow import ApprovalDecision, HighRiskActionApproval


class StateChangeGateDecision(StrEnum):
    ALLOW_OPERATOR_EXECUTION = "allow_operator_execution"
    DENY = "deny"


class StateChangeGateResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: str
    decision: StateChangeGateDecision
    autonomous_execution_allowed: bool = False
    operator_execution_allowed: bool
    reason: str


def evaluate_state_change_gate(
    action_id: str,
    approval: HighRiskActionApproval,
) -> StateChangeGateResult:
    if approval.action_id != action_id:
        return StateChangeGateResult(
            action_id=action_id,
            decision=StateChangeGateDecision.DENY,
            operator_execution_allowed=False,
            reason="approval is bound to a different action",
        )
    if approval.decision != ApprovalDecision.APPROVE:
        return StateChangeGateResult(
            action_id=action_id,
            decision=StateChangeGateDecision.DENY,
            operator_execution_allowed=False,
            reason="high-risk action was not explicitly approved",
        )
    return StateChangeGateResult(
        action_id=action_id,
        decision=StateChangeGateDecision.ALLOW_OPERATOR_EXECUTION,
        operator_execution_allowed=True,
        reason="exact action is approved for operator-controlled execution only",
    )
