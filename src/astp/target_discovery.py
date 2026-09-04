from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from enum import Enum
from ipaddress import ip_address
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from astp.action import canonical_http_target
from astp.models import Engagement, target_in_scope
from astp.observation import HttpObservationEvidence

_LINK_RE = re.compile(r"(?i)(?:href|src)\s*=\s*[\"']([^\"']+)[\"']|https?://[^\s<>\"']+")


class CandidateKind(str, Enum):
    REDIRECT = "redirect"
    LINK = "link"


class CandidateSafety(str, Enum):
    READY_FOR_POLICY = "ready_for_policy"
    OUT_OF_SCOPE = "out_of_scope"
    UNSAFE_SCHEME = "unsafe_scheme"
    HTTPS_DOWNGRADE = "https_downgrade"
    PRIVATE_LITERAL = "private_literal"
    CREDENTIALS_EMBEDDED = "credentials_embedded"
    REDACTED_TARGET = "redacted_target"
    INVALID = "invalid"


class DiscoveryProvenance(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_id: str
    source_action_id: str
    source_target: str
    source_kind: CandidateKind
    observed_at: datetime


class TargetCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    schema_version: str = "1"
    id: str
    canonical_target: str | None
    display_target: str
    kind: CandidateKind
    safety: CandidateSafety
    in_scope: bool
    same_origin: bool = False
    requires_new_permit: bool = True
    requires_semantic_assessment: bool = False
    executable: bool = False
    reason: str
    provenance: tuple[DiscoveryProvenance, ...]
    discovered_at: datetime


class TargetDiscoveryResult(BaseModel):
    schema_version: str = "1"
    source_evidence_id: str
    candidates: list[TargetCandidate] = Field(default_factory=list)


def _candidate_id(
    kind: CandidateKind, canonical_target: str | None, source_evidence_id: str
) -> str:
    payload = {
        "kind": kind.value,
        "target": canonical_target,
        "source_evidence_id": source_evidence_id,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return f"target-{digest}"


def _same_origin(source: str, target: str) -> bool:
    a = urlsplit(source)
    b = urlsplit(target)
    if not a.hostname or not b.hostname:
        return False
    a_port = a.port or (443 if a.scheme.lower() == "https" else 80)
    b_port = b.port or (443 if b.scheme.lower() == "https" else 80)
    return (
        a.scheme.lower() == b.scheme.lower()
        and a.hostname.lower() == b.hostname.lower()
        and a_port == b_port
    )


def _literal_address_is_private(hostname: str) -> bool:
    normalized = hostname.strip().lower().rstrip(".")
    if normalized in {"localhost", "localhost.localdomain"}:
        return True
    try:
        address = ip_address(normalized)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def assess_discovered_target(
    *,
    source_target: str,
    discovered_target: str,
    engagement: Engagement,
) -> tuple[str | None, CandidateSafety, bool, bool, str]:
    if "[REDACTED]" in discovered_target:
        return (
            None,
            CandidateSafety.REDACTED_TARGET,
            False,
            False,
            ("Target contains redacted material and cannot be promoted to execution."),
        )

    try:
        parsed = urlsplit(discovered_target)
        if parsed.scheme.lower() not in {"http", "https"}:
            return (
                None,
                CandidateSafety.UNSAFE_SCHEME,
                False,
                False,
                ("Only HTTP(S) discoveries may become observation candidates."),
            )
        if not parsed.hostname:
            return None, CandidateSafety.INVALID, False, False, "Target has no hostname."
        if parsed.username is not None or parsed.password is not None:
            return (
                None,
                CandidateSafety.CREDENTIALS_EMBEDDED,
                False,
                False,
                ("Credentials embedded in discovered URLs are never executable."),
            )
        canonical = canonical_http_target(discovered_target)
    except (ValueError, TypeError):
        return None, CandidateSafety.INVALID, False, False, "Target is not a valid HTTP URL."

    source = urlsplit(source_target)
    target = urlsplit(canonical)
    same_origin = _same_origin(source_target, canonical)
    in_scope = target_in_scope(canonical, engagement.scope)

    if source.scheme.lower() == "https" and target.scheme.lower() == "http":
        return (
            canonical,
            CandidateSafety.HTTPS_DOWNGRADE,
            in_scope,
            same_origin,
            ("HTTPS-to-HTTP downgrade is not auto-promotable."),
        )
    if target.hostname and _literal_address_is_private(target.hostname):
        return (
            canonical,
            CandidateSafety.PRIVATE_LITERAL,
            in_scope,
            same_origin,
            ("Private/loopback/link-local literal destinations are not auto-promotable."),
        )
    if not in_scope:
        return (
            canonical,
            CandidateSafety.OUT_OF_SCOPE,
            False,
            same_origin,
            ("Discovered target is outside current engagement scope."),
        )
    return (
        canonical,
        CandidateSafety.READY_FOR_POLICY,
        True,
        same_origin,
        (
            "Candidate passed deterministic discovery safety checks and still requires "
            "policy evaluation."
        ),
    )


def _make_candidate(
    *,
    evidence: HttpObservationEvidence,
    raw_target: str,
    kind: CandidateKind,
    engagement: Engagement,
    now: datetime,
) -> TargetCandidate:
    absolute = urljoin(evidence.target, raw_target)
    canonical, safety, in_scope, same_origin, reason = assess_discovered_target(
        source_target=evidence.target,
        discovered_target=absolute,
        engagement=engagement,
    )
    provenance = DiscoveryProvenance(
        evidence_id=evidence.evidence_id,
        source_action_id=evidence.action_id,
        source_target=evidence.target,
        source_kind=kind,
        observed_at=evidence.observed_at,
    )
    return TargetCandidate(
        id=_candidate_id(kind, canonical, evidence.evidence_id),
        canonical_target=canonical,
        display_target=absolute,
        kind=kind,
        safety=safety,
        in_scope=in_scope,
        same_origin=same_origin,
        requires_new_permit=True,
        requires_semantic_assessment=bool(engagement.constraints.semantic_exclusions),
        executable=False,
        reason=reason,
        provenance=(provenance,),
        discovered_at=now,
    )


def discover_targets_from_evidence(
    evidence: HttpObservationEvidence,
    engagement: Engagement,
    *,
    include_links: bool = True,
    max_link_candidates: int = 50,
    now: datetime | None = None,
) -> TargetDiscoveryResult:
    current = now or datetime.now(UTC)
    candidates: list[TargetCandidate] = []

    if evidence.redirect is not None:
        candidates.append(
            _make_candidate(
                evidence=evidence,
                raw_target=evidence.redirect.target,
                kind=CandidateKind.REDIRECT,
                engagement=engagement,
                now=current,
            )
        )

    if include_links and evidence.body_preview:
        seen: set[str] = set()
        for match in _LINK_RE.finditer(evidence.body_preview):
            raw = match.group(1) or match.group(0)
            raw = raw.strip()
            if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                continue
            absolute = urljoin(evidence.target, raw)
            if absolute in seen:
                continue
            seen.add(absolute)
            candidates.append(
                _make_candidate(
                    evidence=evidence,
                    raw_target=raw,
                    kind=CandidateKind.LINK,
                    engagement=engagement,
                    now=current,
                )
            )
            if len(seen) >= max_link_candidates:
                break

    return TargetDiscoveryResult(
        source_evidence_id=evidence.evidence_id,
        candidates=candidates,
    )
