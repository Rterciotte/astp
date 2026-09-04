from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel, Field

from astp.browser_intake import BrowserCapture, capture_to_text, write_capture
from astp.io import dump_yaml, load_model
from astp.program_intake import import_program_text
from astp.program_models import BugBountyProgram


class ProgramPageType(str, Enum):
    PROGRAM_LISTING = "program_listing"
    PROGRAM_DETAIL = "program_detail"
    UNKNOWN = "unknown"


class ProgramSyncStatus(str, Enum):
    DISCOVERED = "discovered"
    SYNCED = "synced"
    NEEDS_REVIEW = "needs_review"
    FAILED = "failed"


class ProgramCandidate(BaseModel):
    id: str
    name: str
    detail_url: str
    platform: str
    summary: str | None = None


class CatalogProgram(BaseModel):
    candidate: ProgramCandidate
    sync_status: ProgramSyncStatus = ProgramSyncStatus.DISCOVERED
    normalized_path: str | None = None
    capture_path: str | None = None
    content_sha256: str | None = None
    last_synced_at: datetime | None = None
    error: str | None = None
    active: bool = False


class BugBountyWorkspace(BaseModel):
    schema_version: str = "1"
    platform: str
    source_url: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    programs: list[CatalogProgram] = Field(default_factory=list)

    def active_programs(self) -> list[CatalogProgram]:
        return [item for item in self.programs if item.active]


class ProgramDiscoveryResult(BaseModel):
    page_type: ProgramPageType
    candidates: list[ProgramCandidate] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


_DETAIL_MARKERS = (
    "/program/detail",
    "/programs/detail",
    "/program/detail/",
    "/programs/",
)
_EXCLUDED_LINK_MARKERS = (
    "/report",
    "/ranking",
    "/account",
    "/login",
    "/logout",
    "/vault",
    "/vaga",
)


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized or "program"


def _candidate_id(platform: str, name: str, url: str) -> str:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    return f"{_slug(platform)}-{_slug(name)}-{digest}"


def classify_program_page(capture: BrowserCapture) -> ProgramPageType:
    lowered = capture.text.lower()
    detail_signals = sum(
        marker in lowered
        for marker in (
            "política do programa",
            "politica do programa",
            "exclusão de endpoints",
            "exclusao de endpoints",
            "lista de escopo do programa",
            "recompensas com valores financeiros",
        )
    )
    listing_signals = sum(
        marker in lowered
        for marker in (
            "programas timeline",
            "mostrando",
            "publicado há",
            "publicado ha",
        )
    )
    detail_links = sum(_looks_like_detail_url(link.get("href", "")) for link in capture.links)
    if detail_signals >= 2:
        return ProgramPageType.PROGRAM_DETAIL
    if listing_signals >= 2 or detail_links >= 2:
        return ProgramPageType.PROGRAM_LISTING
    return ProgramPageType.UNKNOWN


def _looks_like_detail_url(url: str) -> bool:
    lowered = url.lower()
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if any(marker in lowered for marker in _EXCLUDED_LINK_MARKERS):
        return False
    if any(marker in lowered for marker in _DETAIL_MARKERS):
        return True
    return "program" in parsed.path.lower() and bool(parsed.query)


def discover_programs(capture: BrowserCapture, *, platform: str) -> ProgramDiscoveryResult:
    page_type = classify_program_page(capture)
    base = capture.url
    origin = urlparse(base)
    candidates: list[ProgramCandidate] = []
    seen: set[str] = set()

    for link in capture.links:
        raw_href = link.get("href", "").strip()
        if not raw_href:
            continue
        href = urljoin(base, raw_href)
        parsed = urlparse(href)
        if parsed.netloc != origin.netloc or not _looks_like_detail_url(href):
            continue
        name = link.get("text", "").strip()
        context = link.get("context", "").strip()
        if not name and context:
            name = context.splitlines()[0].strip()
        if not name:
            continue
        name = re.sub(r"\s+", " ", name)[:160].strip()
        if href in seen:
            continue
        seen.add(href)
        candidates.append(
            ProgramCandidate(
                id=_candidate_id(platform, name, href),
                name=name,
                detail_url=href,
                platform=platform,
                summary=context[:1000] or None,
            )
        )

    warnings: list[str] = []
    if page_type == ProgramPageType.PROGRAM_DETAIL:
        warnings.append("Current page appears to be one program detail page, not a listing.")
    if not candidates:
        warnings.append(
            "No authenticated program detail links were discovered on the current page."
        )
    return ProgramDiscoveryResult(page_type=page_type, candidates=candidates, warnings=warnings)


def load_or_create_workspace(
    path: Path,
    *,
    platform: str,
    source_url: str,
) -> BugBountyWorkspace:
    if path.exists():
        return load_model(path, BugBountyWorkspace)
    return BugBountyWorkspace(platform=platform, source_url=source_url)


def merge_discovery(
    workspace: BugBountyWorkspace,
    result: ProgramDiscoveryResult,
) -> BugBountyWorkspace:
    existing = {item.candidate.detail_url: item for item in workspace.programs}
    merged: list[CatalogProgram] = []
    for candidate in result.candidates:
        item = existing.pop(candidate.detail_url, None)
        if item is None:
            item = CatalogProgram(candidate=candidate)
        else:
            item.candidate = candidate
        merged.append(item)
    merged.extend(existing.values())
    workspace.programs = merged
    workspace.discovered_at = datetime.now(UTC)
    return workspace


def save_workspace(workspace: BugBountyWorkspace, path: Path) -> None:
    dump_yaml(workspace, path)


def sync_program_capture(
    workspace: BugBountyWorkspace,
    *,
    candidate_id: str,
    capture: BrowserCapture,
    catalog_path: Path,
    captures_dir: Path,
    programs_dir: Path,
) -> BugBountyProgram:
    item = next(
        (entry for entry in workspace.programs if entry.candidate.id == candidate_id),
        None,
    )
    if item is None:
        raise ValueError(f"unknown program candidate: {candidate_id}")

    page_type = classify_program_page(capture)
    if page_type != ProgramPageType.PROGRAM_DETAIL:
        item.sync_status = ProgramSyncStatus.FAILED
        item.error = f"expected program_detail, got {page_type.value}"
        save_workspace(workspace, catalog_path)
        raise ValueError(item.error)

    capture_path = captures_dir / f"{candidate_id}.json"
    receipt = write_capture(capture, capture_path)
    program = import_program_text(
        capture_to_text(capture),
        name=item.candidate.name,
        platform=item.candidate.platform,
        source_type="authenticated_browser",
        source_url=capture.url,
    )
    program.source.title = capture.title
    program.source.captured_at = capture.captured_at

    program_path = programs_dir / f"{candidate_id}.yaml"
    dump_yaml(program, program_path)
    item.capture_path = str(capture_path)
    item.normalized_path = str(program_path)
    item.content_sha256 = receipt.sha256
    item.last_synced_at = datetime.now(UTC)
    item.error = None
    item.sync_status = (
        ProgramSyncStatus.NEEDS_REVIEW if program.issues else ProgramSyncStatus.SYNCED
    )
    save_workspace(workspace, catalog_path)
    return program


def set_active_programs(
    workspace: BugBountyWorkspace,
    program_ids: set[str],
) -> BugBountyWorkspace:
    known = {item.candidate.id for item in workspace.programs}
    unknown = program_ids - known
    if unknown:
        raise ValueError("unknown program ids: " + ", ".join(sorted(unknown)))
    for item in workspace.programs:
        item.active = item.candidate.id in program_ids
    return workspace
