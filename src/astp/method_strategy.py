from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class ObservationMethodReason(str, Enum):
    METADATA_FIRST = "metadata_first"
    BODY_REQUIRED = "body_required"


class ObservationMethodChoice(BaseModel):
    method: str
    reason: ObservationMethodReason


def choose_observation_method(*, body_required: bool = False) -> ObservationMethodChoice:
    if body_required:
        return ObservationMethodChoice(method="GET", reason=ObservationMethodReason.BODY_REQUIRED)
    return ObservationMethodChoice(method="HEAD", reason=ObservationMethodReason.METADATA_FIRST)
