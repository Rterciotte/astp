from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict, field_validator


class PhysicalImageIdentity(BaseModel):
    """Immutable identity captured from a locally built Docker image."""

    model_config = ConfigDict(frozen=True)

    runtime_id: str
    image_tag: str
    image_id: str
    repo_digest: str | None = None
    build_manifest_hash: str

    @field_validator("runtime_id", "image_tag", "build_manifest_hash")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("image identity fields cannot be blank")
        return value

    @field_validator("image_id")
    @classmethod
    def valid_image_id(cls, value: str) -> str:
        if not value.startswith("sha256:") or len(value) != 71:
            raise ValueError("Docker image id must be a full sha256 digest")
        return value

    def immutable_digest(self) -> str:
        return self.repo_digest or self.image_id

    def identity_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()


def parse_repo_digest(raw: str) -> str | None:
    """Extract a digest from `docker image inspect` RepoDigests JSON output."""
    text = raw.strip()
    if not text or text in {"null", "[]"}:
        return None
    parsed = json.loads(text)
    if not isinstance(parsed, list):
        raise TypeError("RepoDigests output must be a JSON list")
    for item in parsed:
        if not isinstance(item, str) or "@sha256:" not in item:
            continue
        digest = "sha256:" + item.rsplit("@sha256:", 1)[1]
        if len(digest) == 71:
            return digest
    return None
