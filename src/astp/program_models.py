from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from astp.models import ScopeRule, SemanticExclusionRule


class ProgramImportStatus(str, Enum):
    READY = "ready"
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
    provenance: list[RuleProvenance] = Field(default_factory=list)

    @field_validator("provenance", mode="before")
    @classmethod
    def accept_legacy_single_provenance(cls, value: Any) -> Any:
        """Load M2.5.2 YAML where constraint provenance was one object."""
        if isinstance(value, dict):
            return [value]
        return value


class ProgramIssueResolution(BaseModel):
    resolution_type: str
    reviewed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    note: str | None = None
    operator_value: str | float | bool | None = None
    added_denies: list[ScopeRule] = Field(default_factory=list)


class ProgramIssue(BaseModel):
    code: str
    message: str
    source_text: str | None = None
    blocking: bool = True
    resolution: ProgramIssueResolution | None = None

    @property
    def resolved(self) -> bool:
        return self.resolution is not None


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
    reviewed_max_requests_per_second: float | None = None
    semantic_exclusions: list[SemanticExclusionRule] = Field(default_factory=list)
    source: ProgramSourceSnapshot
    issues: list[ProgramIssue] = Field(default_factory=list)

    @property
    def unresolved_issues(self) -> list[ProgramIssue]:
        return [issue for issue in self.issues if issue.blocking and not issue.resolved]

    @property
    def status(self) -> ProgramImportStatus:
        return (
            ProgramImportStatus.NEEDS_REVIEW
            if self.unresolved_issues
            else ProgramImportStatus.READY
        )

    def allowed_scope(self) -> list[ScopeRule]:
        return [entry.selector for entry in self.scope if entry.effect == RuleEffect.ALLOW]

    def denied_scope(self) -> list[ScopeRule]:
        return [entry.selector for entry in self.scope if entry.effect == RuleEffect.DENY]
