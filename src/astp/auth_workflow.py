from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class AuthWorkflowKind(StrEnum):
    MAP = "authentication_workflow_mapping"
    SESSION_ROTATION = "session_rotation"
    LOGOUT_INVALIDATION = "logout_invalidation"
    PASSWORD_CHANGE_INVALIDATION = "password_change_invalidation"
    RESET_TOKEN = "reset_token_workflow"
    OAUTH_STATE = "oauth_state"
    REDIRECT_URI = "redirect_uri_validation"
    PKCE = "pkce"
    SESSION_FIXATION = "session_fixation"
    MFA = "mfa_workflow"
    PRIVILEGE_TRANSITION = "privilege_transition"


class SecretRef(BaseModel):
    ref: str = Field(pattern=r"^[A-Za-z0-9_.:/-]+$")


class IdentityRef(BaseModel):
    ref: str = Field(pattern=r"^[A-Za-z0-9_.:/-]+$")
    secret_refs: tuple[SecretRef, ...] = ()


class AuthWorkflowPlan(BaseModel):
    kind: AuthWorkflowKind
    target: str
    identity_refs: tuple[IdentityRef, ...] = ()
    state_changing: bool = False
    cleanup_strategy: str | None = None
    requires_policy_decision: bool = True
    requires_fresh_permit: bool = True

    def blockers(self) -> tuple[str, ...]:
        rows: list[str] = []
        if self.kind is not AuthWorkflowKind.MAP and not self.identity_refs:
            rows.append("blocked_prerequisite: configured identity reference required")
        if self.state_changing and not self.cleanup_strategy:
            rows.append("blocked_prerequisite: state-changing workflow requires cleanup strategy")
        return tuple(rows)
