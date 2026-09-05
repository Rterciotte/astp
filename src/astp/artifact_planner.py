from __future__ import annotations

import hashlib
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from astp.javascript_inventory import JavaScriptInventory


class ArtifactPlanStatus(str, Enum):
    NEEDS_POLICY = "needs_policy"
    BLOCKED = "blocked"


class ArtifactFetchCandidate(BaseModel):
    id: str
    target: str
    status: ArtifactPlanStatus = ArtifactPlanStatus.NEEDS_POLICY
    requires_new_permit: bool = True
    reason: str = "Artifact discovery does not authorize retrieval."


class ArtifactFetchPlan(BaseModel):
    schema_version: str = "1"
    items: list[ArtifactFetchCandidate] = Field(default_factory=list)
    network_performed: bool = False


def plan_javascript_artifacts(inventory: JavaScriptInventory) -> ArtifactFetchPlan:
    items: list[ArtifactFetchCandidate] = []
    for artifact in inventory.artifacts:
        parsed = urlsplit(artifact.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        digest = hashlib.sha256(artifact.url.encode()).hexdigest()[:16]
        items.append(ArtifactFetchCandidate(id=f"artifact-plan-{digest}", target=artifact.url))
    return ArtifactFetchPlan(items=items)
