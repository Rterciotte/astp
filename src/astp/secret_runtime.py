from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from astp.secret_broker import SecretReference


@dataclass(frozen=True, repr=False)
class ResolvedSecret:
    reference_id: str
    value: str

    def __repr__(self) -> str:
        return f"ResolvedSecret(reference_id={self.reference_id!r}, value='[REDACTED]')"


def resolve_secret_reference(
    reference: SecretReference,
    *,
    environment: Mapping[str, str] | None = None,
) -> ResolvedSecret:
    if reference.provider != "env":
        raise ValueError("only env secret references are executable in the current runtime")
    source = os.environ if environment is None else environment
    value = source.get(reference.locator)
    if not value:
        raise ValueError(f"secret reference {reference.id} is unavailable")
    return ResolvedSecret(reference_id=reference.id, value=value)
