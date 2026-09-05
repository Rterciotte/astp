from __future__ import annotations

from pydantic import BaseModel, Field

from astp.assessment import AssessmentResult


class FieldValidationCheck(BaseModel):
    name: str
    passed: bool
    detail: str


class FieldValidationResult(BaseModel):
    checks: list[FieldValidationCheck] = Field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.checks)


def validate_assessment_recovery(result: AssessmentResult) -> FieldValidationResult:
    return FieldValidationResult(
        checks=[
            FieldValidationCheck(
                name="no_implicit_network",
                passed=not result.network_execution_performed,
                detail="Offline assessment must not perform target network execution.",
            ),
            FieldValidationCheck(
                name="invalid_evidence_quarantined",
                passed=all(
                    evidence_id not in {signal.evidence_id for signal in result.signals}
                    for evidence_id in result.invalid_evidence_ids
                ),
                detail="Integrity-invalid evidence must not contribute normalized signals.",
            ),
            FieldValidationCheck(
                name="report_generated",
                passed=bool(result.report_markdown.strip()),
                detail="Assessment report must be generated from accepted evidence.",
            ),
        ]
    )
