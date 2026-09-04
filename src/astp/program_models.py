from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, Field

from astp.models import ScopeRule


class ProgramImportStatus(str, Enum):
    CLEAN = "clean"
    NEEDS_REVIEW = "needs_review"


class ProgramVisibility(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"
    UNKNOWN = "unknown"


class ProgramOperationalStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class RuleEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    RESTRICT = "restrict"
    INFO = "info"


class RuleProvenance(BaseModel):
    source_type: str
    source_url: str | None = None
    section: str | None = None
    source_text: str
    captured_at: datetime | None = None


class ProgramScopeEntry(BaseModel):
    effect: RuleEffect
    selector: ScopeRule
    provenance: RuleProvenance
    label: str | None = None


class ProgramConstraint(BaseModel):
    code: str
    effect: RuleEffect = RuleEffect.RESTRICT
    value: str | bool | float | None = None
    provenance: RuleProvenance


class ProgramIssue(BaseModel):
    code: str
    message: str
    source_text: str | None = None


class ProgramSourceSnapshot(BaseModel):
    source_type: str
    source_url: str | None = None
    title: str | None = None
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    content_sha256: str


class BugBountyProgram(BaseModel):
    id: str
    name: str
    platform: str
    visibility: ProgramVisibility = ProgramVisibility.UNKNOWN
    operational_status: ProgramOperationalStatus = ProgramOperationalStatus.UNKNOWN
    scope: list[ProgramScopeEntry] = Field(default_factory=list)
    constraints: list[ProgramConstraint] = Field(default_factory=list)
    excluded_finding_types: list[str] = Field(default_factory=list)
    recommended_user_agent: str | None = None
    source: ProgramSourceSnapshot
    issues: list[ProgramIssue] = Field(default_factory=list)

    @property
    def status(self) -> ProgramImportStatus:
        return ProgramImportStatus.NEEDS_REVIEW if self.issues else ProgramImportStatus.CLEAN

    def allowed_scope(self) -> list[ScopeRule]:
        return [entry.selector for entry in self.scope if entry.effect == RuleEffect.ALLOW]

    def denied_scope(self) -> list[ScopeRule]:
        return [entry.selector for entry in self.scope if entry.effect == RuleEffect.DENY]
