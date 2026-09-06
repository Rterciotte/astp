from __future__ import annotations

import hashlib
import re
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class JavascriptSignalKind(str, Enum):
    ROUTE_HINT = "route_hint"
    SOURCE_MAP_HINT = "source_map_hint"
    FRAMEWORK_HINT = "framework_hint"
    API_HINT = "api_hint"
    ABSOLUTE_URL_HINT = "absolute_url_hint"
    NETWORK_CALL_HINT = "network_call_hint"


class JavascriptStaticSignal(BaseModel):
    id: str
    kind: JavascriptSignalKind
    value: str
    confidence: float
    vulnerability_confirmed: bool = False


class JavascriptStaticAnalysis(BaseModel):
    schema_version: str = "2"
    artifact_sha256: str
    artifact_size_bytes: int = 0
    source_evidence_id: str | None = None
    source_permit_id: str | None = None
    source_target: str | None = None
    artifact_integrity_verified: bool = False
    signals: list[JavascriptStaticSignal] = Field(default_factory=list)
    network_performed: bool = False


def _signal(kind: JavascriptSignalKind, value: str, confidence: float) -> JavascriptStaticSignal:
    digest = hashlib.sha256(f"{kind.value}|{value}".encode()).hexdigest()[:16]
    return JavascriptStaticSignal(
        id=f"js-signal-{digest}", kind=kind, value=value, confidence=confidence
    )


def analyze_javascript_bytes(data: bytes) -> JavascriptStaticAnalysis:
    text = data.decode("utf-8", errors="replace")
    signals: dict[tuple[str, str], JavascriptStaticSignal] = {}
    patterns = [
        (JavascriptSignalKind.API_HINT, r"[\"'](/api/[A-Za-z0-9_./?=&%-]+)[\"']", 0.82),
        (
            JavascriptSignalKind.ROUTE_HINT,
            r"[\"'](/(?:app|admin|account|graphql)[A-Za-z0-9_./?=&%-]*)[\"']",
            0.68,
        ),
        (
            JavascriptSignalKind.ABSOLUTE_URL_HINT,
            r"[\"'](https?://[^\"'`\\s<>]+)[\"']",
            0.70,
        ),
    ]
    for kind, pattern, confidence in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(1)
            signals[(kind.value, value)] = _signal(kind, value, confidence)

    for call in ("fetch", "XMLHttpRequest", "WebSocket", "axios"):
        if re.search(rf"\b{re.escape(call)}\b", text, flags=re.IGNORECASE):
            signals[(JavascriptSignalKind.NETWORK_CALL_HINT.value, call)] = _signal(
                JavascriptSignalKind.NETWORK_CALL_HINT, call, 0.65
            )

    if "sourceMappingURL=" in text:
        signals[(JavascriptSignalKind.SOURCE_MAP_HINT.value, "sourceMappingURL")] = _signal(
            JavascriptSignalKind.SOURCE_MAP_HINT, "sourceMappingURL", 0.95
        )
    framework_markers = {
        "__NEXT_DATA__": "Next.js",
        "TURBOPACK": "Next.js/Turbopack",
        "webpackChunk": "Webpack",
        "__NUXT__": "Nuxt",
        "React.createElement": "React",
    }
    for marker, framework in framework_markers.items():
        if marker in text:
            signals[(JavascriptSignalKind.FRAMEWORK_HINT.value, framework)] = _signal(
                JavascriptSignalKind.FRAMEWORK_HINT, framework, 0.75
            )
    return JavascriptStaticAnalysis(
        artifact_sha256=hashlib.sha256(data).hexdigest(),
        artifact_size_bytes=len(data),
        signals=sorted(signals.values(), key=lambda item: (item.kind.value, item.value)),
    )


def analyze_javascript_text(text: str) -> JavascriptStaticAnalysis:
    return analyze_javascript_bytes(text.encode())


def analyze_javascript_file(path: Path) -> JavascriptStaticAnalysis:
    return analyze_javascript_bytes(path.read_bytes())
