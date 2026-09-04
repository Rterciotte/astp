from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from astp.models import RiskClass, TestDefinition


class ExecutionStrategy(str, Enum):
    OBSERVE_HTTP = "observe_http"
    DIFFERENTIAL_REQUEST = "differential_request"
    STATIC_ANALYSIS = "static_analysis"
    MANUAL = "manual"


class EvidenceRequirements(BaseModel):
    required: list[str] = Field(default_factory=list)


class StandardsMapping(BaseModel):
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    asvs: list[str] = Field(default_factory=list)


class SecurityTestDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    id: str
    title: str
    category: str
    risk_class: RiskClass
    preconditions: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    execution_strategy: ExecutionStrategy
    success_conditions: list[str] = Field(default_factory=list)
    evidence: EvidenceRequirements = Field(default_factory=EvidenceRequirements)
    standards: StandardsMapping = Field(default_factory=StandardsMapping)
    description: str = ""

    @model_validator(mode="after")
    def observation_strategy_is_non_state_changing(self) -> SecurityTestDefinition:
        if self.execution_strategy == ExecutionStrategy.OBSERVE_HTTP and self.risk_class not in {
            RiskClass.PASSIVE,
            RiskClass.SAFE_ACTIVE,
        }:
            raise ValueError("observe_http DSL tests must be passive or safe_active")
        return self

    def to_runtime_test(self) -> TestDefinition:
        return TestDefinition(
            id=self.id,
            title=self.title,
            category=self.category,
            risk_class=self.risk_class,
            required_context=list(self.preconditions),
            evidence_required=list(self.evidence.required),
            description=self.description,
        )
