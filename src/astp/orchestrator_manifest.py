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
    return all(
        (root / name).is_file() and hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
        for name, digest in manifest.artifacts.items()
    )
