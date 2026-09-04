from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RiskClass(str, Enum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe_active"
    STATE_CHANGING = "state_changing"
    INTRUSIVE = "intrusive"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    INSUFFICIENT_CONTEXT = "insufficient_context"


class SemanticExclusionKind(str, Enum):
    PRODUCT_FAMILY = "product_family"
    ORGANIZATION_FAMILY = "organization_family"
    ASSET_FAMILY = "asset_family"


class SemanticExclusionRule(BaseModel):
    id: str
    kind: SemanticExclusionKind
    value: str
    source_text: str | None = None


class ScopeKind(str, Enum):
    DOMAIN = "domain"
    WILDCARD_DOMAIN = "wildcard_domain"
    URL_PREFIX = "url_prefix"
    CIDR = "cidr"


class ScopeRule(BaseModel):
    kind: ScopeKind
    value: str

    @field_validator("value")
    @classmethod
    def non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("scope value cannot be empty")
        return value


class ScopePolicy(BaseModel):
    allowed: list[ScopeRule] = Field(default_factory=list)
    denied: list[ScopeRule] = Field(default_factory=list)
    approval_required: list[ScopeRule] = Field(default_factory=list)


class MethodPolicy(BaseModel):
    passive: Decision = Decision.ALLOW
    safe_active: Decision = Decision.ALLOW
    state_changing: Decision = Decision.APPROVAL_REQUIRED
    intrusive: Decision = Decision.DENY

    def decision_for(self, risk: RiskClass) -> Decision:
        return Decision(getattr(self, risk.value))


class AssetConstraint(BaseModel):
    selector: ScopeRule
    allowed_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_http_methods: list[str] = Field(default_factory=list)
    allowed_identities: list[str] = Field(default_factory=list)
    max_requests_per_second: float | None = Field(default=None, gt=0, le=1000)

    @field_validator("allowed_ports")
    @classmethod
    def valid_ports(cls, ports: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError("ports must be between 1 and 65535")
        return ports

    @field_validator("allowed_http_methods")
    @classmethod
    def normalize_methods(cls, methods: list[str]) -> list[str]:
        return [method.upper() for method in methods]

    @field_validator("allowed_paths", "denied_paths")
    @classmethod
    def normalize_paths(cls, paths: list[str]) -> list[str]:
        return [path if path.startswith("/") else f"/{path}" for path in paths]


class RedactionProfile(BaseModel):
    sensitive_headers: set[str] = Field(default_factory=set)
    sensitive_query_parameters: set[str] = Field(default_factory=set)
    sensitive_body_fields: set[str] = Field(default_factory=set)

    @field_validator(
        "sensitive_headers",
        "sensitive_query_parameters",
        "sensitive_body_fields",
    )
    @classmethod
    def normalize_names(cls, values: set[str]) -> set[str]:
        return {value.strip().lower() for value in values if value.strip()}


class Constraints(BaseModel):
    max_requests_per_second: float = Field(default=2.0, gt=0, le=1000)
    no_dos: bool = True
    no_social_engineering: bool = True
    no_data_destruction: bool = True
    assets: list[AssetConstraint] = Field(default_factory=list)
    redaction: RedactionProfile = Field(default_factory=RedactionProfile)
    semantic_exclusions: list[SemanticExclusionRule] = Field(default_factory=list)


class Engagement(BaseModel):
    id: str
    name: str
    scope: ScopePolicy
    methods: MethodPolicy = Field(default_factory=MethodPolicy)
    constraints: Constraints = Field(default_factory=Constraints)


class TestDefinition(BaseModel):
    id: str
    title: str
    category: str
    risk_class: RiskClass
    required_context: list[str] = Field(default_factory=list)
    evidence_required: list[str] = Field(default_factory=list)
    description: str = ""


class ApprovalArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    engagement_id: str
    actor: str
    issued_at: datetime
    expires_at: datetime
    targets: tuple[ScopeRule, ...]
    test_ids: tuple[str, ...] = ()
    risk_classes: tuple[RiskClass, ...] = ()
    identities: tuple[str, ...] = ()
    max_requests_per_second: float | None = Field(default=None, gt=0, le=1000)
    reason: str = ""

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def valid_interval(self) -> ApprovalArtifact:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval expires_at must be after issued_at")
        if not self.targets:
            raise ValueError("approval must bind at least one target")
        return self

    def is_active(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        return self.issued_at <= current < self.expires_at


class EvaluationRequest(BaseModel):
    target: str
    available_context: set[str] = Field(default_factory=set)
    approved: bool = False


class EvaluationResult(BaseModel):
    decision: Decision
    target_in_scope: bool
    missing_context: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


def _match_rule(target: str, rule: ScopeRule) -> bool:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = (parsed.hostname or "").lower().rstrip(".")

    if rule.kind == ScopeKind.DOMAIN:
        return host == rule.value.lower().rstrip(".")

    if rule.kind == ScopeKind.WILDCARD_DOMAIN:
        suffix = rule.value.lower().removeprefix("*.").rstrip(".")
        return host == suffix or host.endswith(f".{suffix}")

    if rule.kind == ScopeKind.URL_PREFIX:
        return target.startswith(rule.value)

    if rule.kind == ScopeKind.CIDR:
        try:
            return ip_address(host) in ip_network(rule.value, strict=False)
        except ValueError:
            return False

    return False


def target_in_scope(target: str, scope: ScopePolicy) -> bool:
    if any(_match_rule(target, rule) for rule in scope.denied):
        return False
    return any(_match_rule(target, rule) for rule in scope.allowed)


def evaluate_test(
    engagement: Engagement,
    test: TestDefinition,
    request: EvaluationRequest,
) -> EvaluationResult:
    reasons: list[str] = []
    in_scope = target_in_scope(request.target, engagement.scope)
    if not in_scope:
        return EvaluationResult(
            decision=Decision.DENY,
            target_in_scope=False,
            reasons=["Target is outside the authorized scope or explicitly denied."],
        )

    missing = sorted(set(test.required_context) - request.available_context)
    if missing:
        return EvaluationResult(
            decision=Decision.INSUFFICIENT_CONTEXT,
            target_in_scope=True,
            missing_context=missing,
            reasons=["Required context is missing; execution must not proceed."],
        )

    method_decision = engagement.methods.decision_for(test.risk_class)
    if method_decision == Decision.APPROVAL_REQUIRED and request.approved:
        reasons.append("Explicit approval supplied for this evaluation.")
        method_decision = Decision.ALLOW

    reasons.append(f"Risk class '{test.risk_class.value}' maps to '{method_decision.value}'.")
    return EvaluationResult(
        decision=method_decision,
        target_in_scope=True,
        reasons=reasons,
    )
