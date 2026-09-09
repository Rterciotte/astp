from __future__ import annotations

import hashlib
from pathlib import Path

from pydantic import BaseModel, Field


class CampaignManifest(BaseModel):
    campaign_id: str
    report_state: str
    artifacts: dict[str, str] = Field(default_factory=dict)


def build_campaign_manifest(
    campaign_id: str, artifacts: dict[str, Path], *, report_state: str
) -> CampaignManifest:
    if report_state not in {"interim", "final", "partial"}:
        raise ValueError("invalid report state")
    digests = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in sorted(artifacts.items())
        if path.is_file()
    }
    return CampaignManifest(campaign_id=campaign_id, report_state=report_state, artifacts=digests)


def verify_campaign_manifest(manifest: CampaignManifest, root: Path) -> bool:
    resolved_root = root.resolve()
    for name, digest in manifest.artifacts.items():
        candidate = (root / name).resolve()
        if resolved_root not in candidate.parents or not candidate.is_file():
            return False
        if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            return False
    return True
