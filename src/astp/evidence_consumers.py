from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, Field

from astp.http_fingerprint import fingerprint_http
from astp.js_static_analysis import JavascriptStaticSignal, analyze_javascript_bytes
from astp.observation import HttpObservationEvidence, verify_observation_evidence
from astp.protocol_analyzers import analyze_protocol_posture
from astp.signal_normalizer import NormalizedSignal, normalize_signals
from astp.web_posture import analyze_http_posture


class ContentKind(str, Enum):
    HTML = "html"
    JAVASCRIPT = "javascript"
    JSON = "json"
    OTHER = "other"


class DiscoveredCandidate(BaseModel):
    target: str
    source_evidence_id: str
    source_kind: str
    confidence: float = Field(ge=0, le=1)
    requires_policy_review: bool = True
    network_authorized: bool = False


class EvidenceConsumerRecord(BaseModel):
    evidence_id: str
    target: str
    valid_integrity: bool
    content_kind: ContentKind
    normalized_signals: list[NormalizedSignal] = Field(default_factory=list)
    javascript_signals: list[JavascriptStaticSignal] = Field(default_factory=list)
    discovered_candidates: list[DiscoveredCandidate] = Field(default_factory=list)
    body_artifact_verified: bool = False
    limitations: list[str] = Field(default_factory=list)


class EvidenceConsumerSummary(BaseModel):
    schema_version: str = "1"
    records: list[EvidenceConsumerRecord] = Field(default_factory=list)
    invalid_evidence_ids: list[str] = Field(default_factory=list)
    network_performed: bool = False


_URL_RE = re.compile(r"https?://[^\"'`\s<>]+", re.IGNORECASE)
_HTML_ATTR_RE = re.compile(
    r"(?:href|src|action)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE
)
_PATH_RE = re.compile(r"^/(?!/)[A-Za-z0-9_./?=&%+~:@-]+$")


def _content_kind(evidence: HttpObservationEvidence) -> ContentKind:
    content_type = (evidence.content_type or "").lower()
    path = urlsplit(evidence.target).path.lower()
    if "javascript" in content_type or path.endswith((".js", ".mjs", ".cjs")):
        return ContentKind.JAVASCRIPT
    if "json" in content_type or path.endswith(".json"):
        return ContentKind.JSON
    if "html" in content_type or path.endswith(("/", ".html", ".htm")):
        return ContentKind.HTML
    return ContentKind.OTHER


def _body_artifact_path(evidence: HttpObservationEvidence, evidence_path: Path) -> Path | None:
    artifact = getattr(evidence, "body_artifact", None)
    if artifact is None or not artifact.persisted or not artifact.path:
        return None
    raw = Path(artifact.path)
    candidates = [raw]
    if not raw.is_absolute():
        candidates.extend(
            [
                evidence_path.parent / raw.name,
                Path.cwd() / raw,
            ]
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _candidate(
    target: str, evidence: HttpObservationEvidence, source_kind: str, confidence: float
) -> DiscoveredCandidate:
    return DiscoveredCandidate(
        target=target,
        source_evidence_id=evidence.evidence_id,
        source_kind=source_kind,
        confidence=confidence,
    )


def _collect_html_candidates(
    text: str, evidence: HttpObservationEvidence
) -> list[DiscoveredCandidate]:
    rows: dict[str, DiscoveredCandidate] = {}
    for value in _HTML_ATTR_RE.findall(text):
        value = value.strip()
        if not value or value.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
            continue
        target = urljoin(evidence.target, value)
        if urlsplit(target).scheme.lower() in {"http", "https"}:
            rows[target] = _candidate(target, evidence, "html_attribute", 0.76)
    return sorted(rows.values(), key=lambda item: item.target)


def _walk_json_strings(value: object) -> list[str]:
    rows: list[str] = []
    if isinstance(value, str):
        rows.append(value)
    elif isinstance(value, list):
        for item in value:
            rows.extend(_walk_json_strings(item))
    elif isinstance(value, dict):
        for item in value.values():
            rows.extend(_walk_json_strings(item))
    return rows


def _collect_json_candidates(
    text: str, evidence: HttpObservationEvidence
) -> list[DiscoveredCandidate]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    rows: dict[str, DiscoveredCandidate] = {}
    for value in _walk_json_strings(payload):
        candidate: str | None = None
        if _URL_RE.fullmatch(value):
            candidate = value
        elif _PATH_RE.fullmatch(value):
            candidate = urljoin(evidence.target, value)
        if candidate and urlsplit(candidate).scheme.lower() in {"http", "https"}:
            rows[candidate] = _candidate(candidate, evidence, "json_string", 0.68)
    return sorted(rows.values(), key=lambda item: item.target)


def consume_http_evidence(evidence_path: Path) -> EvidenceConsumerRecord:
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    valid = verify_observation_evidence(evidence)
    kind = _content_kind(evidence)
    limitations: list[str] = []
    if not valid:
        limitations.append(
            "Evidence integrity verification failed; derived signals are suppressed."
        )
        return EvidenceConsumerRecord(
            evidence_id=evidence.evidence_id,
            target=evidence.target,
            valid_integrity=False,
            content_kind=kind,
            limitations=limitations,
        )

    fingerprint = fingerprint_http(evidence)
    protocol = analyze_protocol_posture(evidence)
    posture = analyze_http_posture(evidence)
    normalized = normalize_signals(fingerprint, protocol, posture)
    discovered: list[DiscoveredCandidate] = []
    js_signals: list[JavascriptStaticSignal] = []

    if evidence.redirect is not None and evidence.redirect.location:
        target = urljoin(evidence.target, evidence.redirect.location)
        if urlsplit(target).scheme.lower() in {"http", "https"}:
            discovered.append(_candidate(target, evidence, "redirect_location", 0.95))

    body_path = _body_artifact_path(evidence, evidence_path)
    body_verified = False
    body = None
    if body_path is not None:
        data = body_path.read_bytes()
        artifact = evidence.body_artifact
        body_verified = (
            len(data) == artifact.size_bytes
            and hashlib.sha256(data).hexdigest() == artifact.sha256
        )
        if body_verified:
            body = data
        else:
            limitations.append("Persisted body artifact failed size/SHA-256 verification.")
    elif getattr(evidence, "body_artifact", None) is not None:
        limitations.append("Persisted body artifact could not be located locally.")

    if body is not None:
        text = body.decode("utf-8", errors="replace")
        if kind is ContentKind.JAVASCRIPT:
            analysis = analyze_javascript_bytes(body)
            js_signals = analysis.signals
            for signal in js_signals:
                if signal.kind.value in {"api_hint", "route_hint", "absolute_url_hint"}:
                    target = urljoin(evidence.target, signal.value)
                    if urlsplit(target).scheme.lower() in {"http", "https"}:
                        discovered.append(
                            _candidate(
                                target,
                                evidence,
                                f"javascript_{signal.kind.value}",
                                signal.confidence,
                            )
                        )
        elif kind is ContentKind.HTML:
            discovered.extend(_collect_html_candidates(text, evidence))
        elif kind is ContentKind.JSON:
            discovered.extend(_collect_json_candidates(text, evidence))

    unique = {item.target: item for item in discovered}
    return EvidenceConsumerRecord(
        evidence_id=evidence.evidence_id,
        target=evidence.target,
        valid_integrity=True,
        content_kind=kind,
        normalized_signals=normalized,
        javascript_signals=js_signals,
        discovered_candidates=sorted(unique.values(), key=lambda item: item.target),
        body_artifact_verified=body_verified,
        limitations=limitations,
    )


def consume_evidence_directory(path: Path) -> EvidenceConsumerSummary:
    records: list[EvidenceConsumerRecord] = []
    invalid: list[str] = []
    if not path.exists():
        return EvidenceConsumerSummary()
    for candidate in sorted(path.glob("*.json")):
        try:
            record = consume_http_evidence(candidate)
        except (OSError, ValueError):
            continue
        records.append(record)
        if not record.valid_integrity:
            invalid.append(record.evidence_id)
    return EvidenceConsumerSummary(records=records, invalid_evidence_ids=invalid)
