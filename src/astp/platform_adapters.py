from __future__ import annotations

from datetime import datetime
from typing import Protocol

from pydantic import BaseModel


class PlatformProgram(BaseModel):
    platform: str
    program_id: str
    name: str
    revision: str
    operational: bool | None
    ready: bool


class AuthenticatedSessionHandle(BaseModel):
    provider: str
    opaque_ref: str
    created_at: datetime
    locally_protected: bool = True


class PlatformAdapter(Protocol):
    def discover_programs(self) -> tuple[PlatformProgram, ...]: ...
    def fetch_program_detail(self, program_id: str) -> PlatformProgram: ...
    def refresh_program(self, program_id: str) -> PlatformProgram: ...
    def get_operational_status(self, program_id: str) -> bool | None: ...
    def get_revision(self, program_id: str) -> str: ...
    def supports_authenticated_browser_session(self) -> bool: ...


class BrowserPageReadiness(BaseModel):
    ready: bool
    page_kind: str
    reason: str


def classify_bughunt_page(path: str, text: str, selectors: set[str]) -> BrowserPageReadiness:
    normalized = " ".join(text.lower().split())
    listing = (
        bool({"program-list", "program-card"} & selectors) or "programas disponíveis" in normalized
    )
    detail = "program-detail" in selectors or {"scope", "regras", "recompensas"}.issubset(
        set(normalized.split())
    )
    route_ok = "program" in path.lower() and path.rstrip("/").split("/")[-1] not in {
        "programs",
        "programas",
    }
    if route_ok and detail and not listing and len(normalized) >= 80:
        return BrowserPageReadiness(
            ready=True, page_kind="program_detail", reason="semantic detail markers confirmed"
        )
    return BrowserPageReadiness(
        ready=False,
        page_kind="listing" if listing else "unknown",
        reason="page lacks bounded semantic detail readiness",
    )
