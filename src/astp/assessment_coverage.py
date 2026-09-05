from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AssessmentCoverage(BaseModel):
    model_config = ConfigDict(frozen=True)

    scope: bool
    public_http: bool
    dns_tls: bool
    fingerprinting: bool
    authenticated_http: bool
    authorization_differential: bool
    browser_dynamic: bool
    external_adapters: bool
    active_verification: bool
    reporting: bool
    retest: bool

    @property
    def completed_dimensions(self) -> int:
        values = self.model_dump().values()
        return sum(1 for value in values if value is True)

    @property
    def total_dimensions(self) -> int:
        return len(type(self).model_fields)


def current_assessment_coverage() -> AssessmentCoverage:
    return AssessmentCoverage(
        scope=True,
        public_http=True,
        dns_tls=True,
        fingerprinting=True,
        authenticated_http=True,
        authorization_differential=False,
        browser_dynamic=False,
        external_adapters=False,
        active_verification=False,
        reporting=True,
        retest=True,
    )
