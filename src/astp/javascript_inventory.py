from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, Field

from astp.observation import HttpObservationEvidence

_SCRIPT_RE = re.compile(
    r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_SOURCE_MAP_RE = re.compile(r"//# sourceMappingURL=([^\s]+)")


class JavaScriptArtifact(BaseModel):
    url: str
    evidence_id: str
    source: str
    same_origin_hint: bool
    requires_new_permit: bool = True


class JavaScriptInventory(BaseModel):
    schema_version: str = "1"
    target: str
    artifacts: list[JavaScriptArtifact] = Field(default_factory=list)
    source_maps: list[str] = Field(default_factory=list)
    network_execution_performed: bool = False


def inventory_javascript(evidence: HttpObservationEvidence) -> JavaScriptInventory:
    preview = evidence.body_preview or ""
    artifacts: list[JavaScriptArtifact] = []
    seen: set[str] = set()
    for raw in _SCRIPT_RE.findall(preview):
        url = urljoin(evidence.target, raw.strip())
        if url in seen:
            continue
        seen.add(url)
        artifacts.append(
            JavaScriptArtifact(
                url=url,
                evidence_id=evidence.evidence_id,
                source="html.script.src",
                same_origin_hint=(
                    urlsplit(url).scheme.lower() == urlsplit(evidence.target).scheme.lower()
                    and urlsplit(url).netloc.lower() == urlsplit(evidence.target).netloc.lower()
                ),
            )
        )
    maps = sorted({item.strip() for item in _SOURCE_MAP_RE.findall(preview) if item.strip()})
    return JavaScriptInventory(target=evidence.target, artifacts=artifacts, source_maps=maps)
