from __future__ import annotations

import re

from astp.fingerprint import FingerprintEvidence, FingerprintKind, TechnologyFingerprint
from astp.observation import HttpObservationEvidence

_META_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.IGNORECASE
)
_SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)', re.IGNORECASE)


def _add(
    rows: list[FingerprintEvidence],
    evidence: HttpObservationEvidence,
    kind: FingerprintKind,
    value: str,
    source: str,
    confidence: float,
    *,
    version: str | None = None,
) -> None:
    rows.append(
        FingerprintEvidence(
            kind=kind,
            value=value,
            evidence_id=evidence.evidence_id,
            source=source,
            confidence=confidence,
            version=version,
        )
    )


def fingerprint_http(evidence: HttpObservationEvidence) -> TechnologyFingerprint:
    headers = {name.lower(): value for name, value in evidence.response_headers.items()}
    rows: list[FingerprintEvidence] = []

    server = headers.get("server")
    if server and server != "[REDACTED]":
        name, _, version = server.partition("/")
        _add(
            rows,
            evidence,
            FingerprintKind.SERVER,
            name.strip() or server,
            "header:server",
            0.9,
            version=version.strip() or None,
        )

    powered = headers.get("x-powered-by")
    if powered and powered != "[REDACTED]":
        name, _, version = powered.partition("/")
        _add(
            rows,
            evidence,
            FingerprintKind.FRAMEWORK,
            name.strip() or powered,
            "header:x-powered-by",
            0.85,
            version=version.strip() or None,
        )

    via = headers.get("via", "").lower()
    cf_ray = headers.get("cf-ray")
    if cf_ray or (server is not None and "cloudflare" in server.lower()):
        _add(rows, evidence, FingerprintKind.CDN, "Cloudflare", "response_headers", 0.95)
    elif "cloudfront" in via or "x-amz-cf-id" in headers:
        _add(rows, evidence, FingerprintKind.CDN, "Amazon CloudFront", "response_headers", 0.95)

    content_type = (evidence.content_type or "").lower()
    if "application/json" in content_type or content_type.endswith("+json"):
        _add(rows, evidence, FingerprintKind.API, "JSON API surface", "content-type", 0.8)

    body = evidence.body_preview or ""
    generator = _META_GENERATOR.search(body)
    if generator:
        value = generator.group(1).strip()
        lower = value.lower()
        kind = (
            FingerprintKind.CMS
            if any(x in lower for x in ("wordpress", "drupal", "joomla"))
            else FingerprintKind.FRAMEWORK
        )
        _add(rows, evidence, kind, value, "html:meta-generator", 0.9)

    scripts = _SCRIPT_SRC.findall(body)
    for src in scripts[:20]:
        lowered = src.lower()
        for marker, display in (
            ("jquery", "jQuery"),
            ("react", "React"),
            ("vue", "Vue.js"),
            ("angular", "Angular"),
        ):
            if marker in lowered:
                _add(
                    rows,
                    evidence,
                    FingerprintKind.JAVASCRIPT_LIBRARY,
                    display,
                    f"html:script:{src[:120]}",
                    0.65,
                )
                break

    unique: dict[tuple[str, str, str], FingerprintEvidence] = {}
    for row in rows:
        unique[(row.kind.value, row.value.lower(), row.source)] = row
    return TechnologyFingerprint(
        target=evidence.target,
        evidence_ids=[evidence.evidence_id],
        observations=list(unique.values()),
    )
