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


class JavascriptStaticSignal(BaseModel):
    id: str
    kind: JavascriptSignalKind
    value: str
    confidence: float
    vulnerability_confirmed: bool = False


class JavascriptStaticAnalysis(BaseModel):
    schema_version: str = "1"
    artifact_sha256: str
    signals: list[JavascriptStaticSignal] = Field(default_factory=list)
    network_performed: bool = False


def _signal(kind: JavascriptSignalKind, value: str, confidence: float) -> JavascriptStaticSignal:
    digest = hashlib.sha256(f"{kind.value}|{value}".encode()).hexdigest()[:16]
    return JavascriptStaticSignal(
        id=f"js-signal-{digest}", kind=kind, value=value, confidence=confidence
    )


def analyze_javascript_text(text: str) -> JavascriptStaticAnalysis:
    signals: dict[tuple[str, str], JavascriptStaticSignal] = {}
    patterns = [
        (JavascriptSignalKind.API_HINT, r"[\"'](/api/[A-Za-z0-9_./?=&%-]+)[\"']", 0.82),
        (
            JavascriptSignalKind.ROUTE_HINT,
            r"[\"'](/(?:app|admin|account|graphql)[A-Za-z0-9_./-]*)[\"']",
            0.68,
        ),
    ]
    for kind, pattern, confidence in patterns:
        for match in re.finditer(pattern, text):
            value = match.group(1)
            signals[(kind.value, value)] = _signal(kind, value, confidence)
    if "sourceMappingURL=" in text:
        signals[(JavascriptSignalKind.SOURCE_MAP_HINT.value, "sourceMappingURL")] = _signal(
            JavascriptSignalKind.SOURCE_MAP_HINT, "sourceMappingURL", 0.95
        )
    framework_markers = {
        "__NEXT_DATA__": "Next.js",
        "webpackChunk": "Webpack",
        "__NUXT__": "Nuxt",
        "React.createElement": "React",
    }
    for marker, framework in framework_markers.items():
        if marker in text:
            signals[(JavascriptSignalKind.FRAMEWORK_HINT.value, framework)] = _signal(
                JavascriptSignalKind.FRAMEWORK_HINT, framework, 0.75
            )
    artifact_sha256 = hashlib.sha256(text.encode()).hexdigest()
    return JavascriptStaticAnalysis(
        artifact_sha256=artifact_sha256,
        signals=sorted(signals.values(), key=lambda item: (item.kind.value, item.value)),
    )


def analyze_javascript_file(path: Path) -> JavascriptStaticAnalysis:
    return analyze_javascript_text(path.read_text(encoding="utf-8", errors="replace"))
