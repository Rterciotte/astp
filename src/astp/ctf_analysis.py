from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from astp.ctf_mode import ChallengeDefinition, CtfArtifactRecord, inventory_challenge


class CtfArtifactKind(str, Enum):
    TEXT = "text"
    JSON = "json"
    JAVASCRIPT = "javascript"
    HTML = "html"
    ARCHIVE_ZIP = "archive_zip"
    EXECUTABLE_PE = "executable_pe"
    EXECUTABLE_ELF = "executable_elf"
    IMAGE = "image"
    PCAP = "pcap"
    BINARY = "binary"


class CtfArtifactClassification(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    sha256: str
    size_bytes: int
    kind: CtfArtifactKind
    confidence: float = Field(ge=0, le=1)
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    eligible_adapters: tuple[str, ...] = Field(default_factory=tuple)


class CtfHypothesis(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    artifact_path: str | None = None
    statement: str
    state: str = "open"
    next_adapter: str | None = None
    requires_network: bool = False
    requires_fresh_permit: bool = False


class CtfHypothesisGraph(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    challenge_id: str
    hypotheses: tuple[CtfHypothesis, ...] = Field(default_factory=tuple)


class CtfAnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    challenge_id: str
    classifications: tuple[CtfArtifactClassification, ...] = Field(default_factory=tuple)
    hypothesis_graph: CtfHypothesisGraph
    blockers: tuple[str, ...] = Field(default_factory=tuple)
    network_performed: bool = False


def _classify_bytes(path: str, record: CtfArtifactRecord, data: bytes) -> CtfArtifactClassification:
    lower = path.lower()
    reasons: list[str] = []
    adapters: list[str] = []

    if data.startswith(b"MZ"):
        kind = CtfArtifactKind.EXECUTABLE_PE
        confidence = 0.99
        reasons.append("PE/DOS MZ magic")
        adapters.append("safe-strings")
    elif data.startswith(b"\x7fELF"):
        kind = CtfArtifactKind.EXECUTABLE_ELF
        confidence = 0.99
        reasons.append("ELF magic")
        adapters.append("safe-strings")
    elif data.startswith(b"PK\x03\x04"):
        kind = CtfArtifactKind.ARCHIVE_ZIP
        confidence = 0.99
        reasons.append("ZIP local-file magic")
        adapters.extend(("zip-inventory", "safe-strings"))
    elif data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")):
        kind = CtfArtifactKind.IMAGE
        confidence = 0.98
        reasons.append("recognized image magic")
        adapters.append("safe-strings")
    elif data[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"}:
        kind = CtfArtifactKind.PCAP
        confidence = 0.98
        reasons.append("PCAP/PCAPNG magic")
        adapters.append("safe-strings")
    else:
        decoded: str | None
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            decoded = None
        if decoded is not None:
            stripped = decoded.lstrip()
            if lower.endswith(".json") or stripped.startswith(("{", "[")):
                try:
                    json.loads(decoded)
                except json.JSONDecodeError:
                    pass
                else:
                    kind = CtfArtifactKind.JSON
                    confidence = 0.97
                    reasons.append("valid UTF-8 JSON")
                    adapters.extend(("json-structure", "text-pattern"))
                    return CtfArtifactClassification(
                        path=path,
                        sha256=record.sha256,
                        size_bytes=record.size_bytes,
                        kind=kind,
                        confidence=confidence,
                        reasons=tuple(reasons),
                        eligible_adapters=tuple(adapters),
                    )
            if lower.endswith((".js", ".mjs", ".cjs")):
                kind = CtfArtifactKind.JAVASCRIPT
                confidence = 0.95
                reasons.append("JavaScript extension and UTF-8 text")
            elif lower.endswith((".html", ".htm")) or "<html" in decoded[:4096].lower():
                kind = CtfArtifactKind.HTML
                confidence = 0.94
                reasons.append("HTML extension/marker and UTF-8 text")
            else:
                kind = CtfArtifactKind.TEXT
                confidence = 0.9
                reasons.append("valid UTF-8 text")
            adapters.append("text-pattern")
        else:
            kind = CtfArtifactKind.BINARY
            confidence = 0.75
            reasons.append("unrecognized binary content")
            adapters.append("safe-strings")

    return CtfArtifactClassification(
        path=path,
        sha256=record.sha256,
        size_bytes=record.size_bytes,
        kind=kind,
        confidence=confidence,
        reasons=tuple(reasons),
        eligible_adapters=tuple(adapters),
    )


def analyze_ctf_challenge(challenge: ChallengeDefinition, base_dir: Path) -> CtfAnalysisResult:
    intake = inventory_challenge(challenge, base_dir)
    by_path = {record.path: record for record in intake.artifacts}
    classifications: list[CtfArtifactClassification] = []
    hypotheses: list[CtfHypothesis] = []

    for relative in challenge.artifacts:
        record = by_path.get(relative)
        if record is None:
            continue
        data = (base_dir / relative).read_bytes()
        classification = _classify_bytes(relative, record, data)
        classifications.append(classification)
        adapter = classification.eligible_adapters[0] if classification.eligible_adapters else None
        digest = hashlib.sha256(
            f"{challenge.id}:{relative}:{classification.kind.value}".encode()
        ).hexdigest()[:16]
        hypotheses.append(
            CtfHypothesis(
                id=f"ctf-hyp-{digest}",
                artifact_path=relative,
                statement=(
                    f"Artifact {relative} ({classification.kind.value}) may contain "
                    "challenge-relevant structure or a flag candidate."
                ),
                next_adapter=adapter,
            )
        )

    if challenge.authorized_endpoints:
        digest = hashlib.sha256(f"{challenge.id}:declared-endpoints".encode()).hexdigest()[:16]
        hypotheses.append(
            CtfHypothesis(
                id=f"ctf-hyp-{digest}",
                statement=(
                    "A declared challenge endpoint may expose challenge-relevant HTTP evidence."
                ),
                next_adapter="ctf-observe-http",
                requires_network=True,
                requires_fresh_permit=True,
            )
        )

    return CtfAnalysisResult(
        challenge_id=challenge.id,
        classifications=tuple(classifications),
        hypothesis_graph=CtfHypothesisGraph(
            challenge_id=challenge.id,
            hypotheses=tuple(hypotheses),
        ),
        blockers=intake.blockers,
    )
