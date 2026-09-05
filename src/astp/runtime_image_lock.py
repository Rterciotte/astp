from __future__ import annotations

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field


class RuntimeImageLock(BaseModel):
    model_config = ConfigDict(frozen=True)

    runtime_id: str
    image_reference: str
    image_digest: str
    expected_executable: str
    allowed_operations: tuple[str, ...] = Field(default_factory=tuple)

    def lock_hash(self) -> str:
        payload = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def validate_pinned(self) -> None:
        if not self.image_digest.startswith("sha256:") or len(self.image_digest) != 71:
            raise ValueError("runtime image must be bound to a full sha256 digest")
        if "@sha256:" not in self.image_reference:
            raise ValueError("runtime image reference must be digest-pinned")


def builtin_runtime_image_locks() -> tuple[RuntimeImageLock, ...]:
    # Placeholder digests prevent an unqualified image from being treated as production-ready.
    digest = "sha256:" + "0" * 64
    return (
        RuntimeImageLock(
            runtime_id="playwright.isolated.v1",
            image_reference=f"astp/playwright@{digest}",
            image_digest=digest,
            expected_executable="python",
            allowed_operations=("browser.observe",),
        ),
        RuntimeImageLock(
            runtime_id="security-tools.isolated.v1",
            image_reference=f"astp/security-tools@{digest}",
            image_digest=digest,
            expected_executable="python",
            allowed_operations=(
                "external.nmap.discovery",
                "external.nuclei.safe",
                "external.zap.passive",
            ),
        ),
    )
