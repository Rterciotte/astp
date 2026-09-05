from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class RuntimeArtifactKind(StrEnum):
    OCI_IMAGE = "oci_image"
    LOCAL_DISTRIBUTION = "local_distribution"


class RuntimeArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    kind: RuntimeArtifactKind
    reference: str
    digest: str
    version: str
    capabilities: tuple[str, ...] = Field(default_factory=tuple)
    immutable: bool = True

    @property
    def digest_is_pinned(self) -> bool:
        return self.digest.startswith("sha256:") and len(self.digest) == 71

    def identity_hash(self) -> str:
        payload = f"{self.runtime_id}|{self.reference}|{self.digest}|{self.version}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
