from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.verifier_catalog import VerificationFamily, builtin_verifier_catalog


class VerifierFamilyReadiness(BaseModel):
    model_config = ConfigDict(frozen=True)

    family: VerificationFamily
    definitions: int
    autonomous_safe_definitions: int
    active_definitions: int
    operationally_qualified: bool = False
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def current_verifier_family_readiness() -> tuple[VerifierFamilyReadiness, ...]:
    definitions = builtin_verifier_catalog()
    rows: list[VerifierFamilyReadiness] = []
    for family in VerificationFamily:
        family_defs = [item for item in definitions if item.family is family]
        if not family_defs:
            continue
        active = sum(1 for item in family_defs if item.active_request_required)
        blockers = (
            ()
            if active == 0
            else ("active verifier family lacks a field-qualified execution proof",)
        )
        rows.append(
            VerifierFamilyReadiness(
                family=family,
                definitions=len(family_defs),
                autonomous_safe_definitions=sum(1 for item in family_defs if item.autonomous_safe),
                active_definitions=active,
                operationally_qualified=active == 0,
                blockers=blockers,
            )
        )
    return tuple(rows)
