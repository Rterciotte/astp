from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class TemplateRisk(StrEnum):
    SAFE_READ_ONLY = "safe_read_only"
    SAFE_ACTIVE = "safe_active"
    REVIEW_REQUIRED = "review_required"
    PROHIBITED = "prohibited"


class NucleiTemplateMetadata(BaseModel):
    template_id: str
    methods: tuple[str, ...] = ("GET",)
    requests: int = Field(default=1, ge=1)
    payloads: bool = False
    fuzzing: bool = False
    redirects: bool = False
    headless: bool = False
    code: bool = False
    file_access: bool = False
    oast: bool = False
    network_protocol: bool = False
    state_mutation: bool = False
    dos_marker: bool = False


def classify_nuclei_template(template: NucleiTemplateMetadata) -> TemplateRisk:
    if template.dos_marker or template.state_mutation or template.code or template.file_access:
        return TemplateRisk.PROHIBITED
    if template.oast or template.headless or template.network_protocol:
        return TemplateRisk.REVIEW_REQUIRED
    if (
        template.fuzzing
        or template.payloads
        or any(method not in {"GET", "HEAD", "OPTIONS"} for method in template.methods)
    ):
        return TemplateRisk.SAFE_ACTIVE
    return TemplateRisk.SAFE_READ_ONLY
