from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class BrowserOperation(StrEnum):
    NAVIGATE = "browser.navigate"
    DOM_SNAPSHOT = "browser.dom_snapshot"
    SCREENSHOT = "browser.screenshot"


class BrowserWorkerContract(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability_id: str = "browser.observation.v1"
    operations: tuple[BrowserOperation, ...] = (
        BrowserOperation.NAVIGATE,
        BrowserOperation.DOM_SNAPSHOT,
        BrowserOperation.SCREENSHOT,
    )
    permit_required: bool = True
    redirects_require_reauthorization: bool = True
    form_submission_allowed: bool = False
    file_upload_allowed: bool = False
    arbitrary_script_execution_allowed: bool = False
    state_changing_allowed: bool = False
    runtime_ready: bool = False
    blockers: tuple[str, ...] = Field(default=("isolated Playwright runtime is not bundled yet",))
