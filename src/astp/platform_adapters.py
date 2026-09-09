from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
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


class LocalSpaScenario(StrEnum):
    ROUTE_FIRST = "route_first"
    DOM_FIRST = "dom_first"
    STALE_LISTING = "stale_listing"
    LOADING = "loading"
    SLOW_DETAIL = "slow_detail"
    DETAIL_FAILURE = "detail_failure"
    TIMEOUT = "timeout"
    RECOVERY = "recovery"


class LocalBughuntProgram(PlatformProgram):
    scenario: LocalSpaScenario
    automation_allowed: bool = True
    semantic_excluded_targets: tuple[str, ...] = ()
    rate_limit_rps: float = 1.0


class LocalBughuntAdapter:
    """Deterministic authenticated SPA fixture; it never stores login credentials."""

    def __init__(self, session: AuthenticatedSessionHandle) -> None:
        if not session.locally_protected or not session.opaque_ref:
            raise ValueError("a locally protected authenticated session is required")
        self.session = session
        self.session_valid = True
        scenarios = tuple(LocalSpaScenario)
        self._programs = tuple(
            LocalBughuntProgram(
                platform="local-bughunt",
                program_id=chr(ord("A") + index),
                name=f"Acceptance {chr(ord('A') + index)}",
                revision="1",
                operational=index != 4,
                ready=True,
                scenario=scenario,
                automation_allowed=index != 1,
                semantic_excluded_targets=(
                    ("http://astp-m52-lab:8080/excluded",) if index == 2 else ()
                ),
            )
            for index, scenario in enumerate(scenarios)
        )
        self._attempts: dict[str, int] = {}

    @classmethod
    def authenticated_fixture(cls) -> LocalBughuntAdapter:
        return cls(
            AuthenticatedSessionHandle(
                provider="local-bughunt",
                opaque_ref="session-ref-local-protected",
                created_at=datetime.now(UTC),
            )
        )

    def discover_programs(self) -> tuple[PlatformProgram, ...]:
        self._require_session()
        return self._programs

    def fetch_program_detail(self, program_id: str) -> PlatformProgram:
        self._require_session()
        program = self._get(program_id)
        attempt = self._attempts.get(program_id, 0) + 1
        self._attempts[program_id] = attempt
        path, text, selectors = self._spa_state(program, attempt)
        readiness = classify_bughunt_page(path, text, selectors)
        if not readiness.ready:
            raise TimeoutError(readiness.reason)
        return program

    def refresh_program(self, program_id: str) -> PlatformProgram:
        program = self._get(program_id)
        if program_id == "E":
            program = program.model_copy(update={"operational": True})
        if program_id == "F":
            program = program.model_copy(update={"revision": "2"})
        self._programs = tuple(
            program if row.program_id == program_id else row for row in self._programs
        )
        return program

    def get_operational_status(self, program_id: str) -> bool | None:
        return self._get(program_id).operational

    def get_revision(self, program_id: str) -> str:
        return self._get(program_id).revision

    def supports_authenticated_browser_session(self) -> bool:
        return True

    def expire_session(self) -> None:
        self.session_valid = False

    def _require_session(self) -> None:
        if not self.session_valid:
            raise PermissionError("WAITING_PREREQUISITE: authenticated session expired")

    def _get(self, program_id: str) -> LocalBughuntProgram:
        try:
            return next(row for row in self._programs if row.program_id == program_id)
        except StopIteration as exc:
            raise ValueError("unknown local program") from exc

    @staticmethod
    def _spa_state(program: LocalBughuntProgram, attempt: int) -> tuple[str, str, set[str]]:
        detail_path = f"/program/{program.program_id}"
        detail = (program.name + " scope regras recompensas política detalhes " * 12).strip()
        if program.scenario is LocalSpaScenario.DETAIL_FAILURE:
            raise ConnectionError("local detail navigation failed")
        if program.scenario is LocalSpaScenario.TIMEOUT:
            return detail_path, "loading", {"loading-skeleton"}
        if (
            program.scenario
            in {
                LocalSpaScenario.ROUTE_FIRST,
                LocalSpaScenario.STALE_LISTING,
                LocalSpaScenario.LOADING,
                LocalSpaScenario.SLOW_DETAIL,
            }
            and attempt == 1
        ):
            return detail_path, "Programas disponíveis", {"program-list"}
        if program.scenario is LocalSpaScenario.DOM_FIRST and attempt == 1:
            return "/programs", detail, {"program-detail"}
        return detail_path, detail, {"program-detail"}
