from __future__ import annotations

from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field


class AuthorizedLabProfile(BaseModel):
    model_config = ConfigDict(frozen=True)
    engagement_id: str
    name: str
    allowed_hosts: tuple[str, ...] = Field(default_factory=tuple)
    network_cidr: str | None = None
    explicit_authorization: bool = False


def assert_lab_target(profile: AuthorizedLabProfile, target: str) -> None:
    if not profile.explicit_authorization:
        raise ValueError("lab profile lacks explicit authorization")
    host = (urlsplit(target).hostname or target).strip().lower()
    if host not in {item.lower() for item in profile.allowed_hosts}:
        raise ValueError("target is outside the authorized lab profile")
