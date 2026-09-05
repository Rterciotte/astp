from __future__ import annotations

import importlib.util
from collections.abc import Callable
from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class BrowserRuntimeOperation(StrEnum):
    NAVIGATE = "browser.navigate"
    DOM_SNAPSHOT = "browser.dom_snapshot"
    SCREENSHOT = "browser.screenshot"


class BrowserRuntimeStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    playwright_installed: bool
    runtime_ready: bool
    allowed_operations: tuple[BrowserRuntimeOperation, ...]
    state_changing_allowed: bool = False
    arbitrary_script_allowed: bool = False


def browser_runtime_status() -> BrowserRuntimeStatus:
    installed = importlib.util.find_spec("playwright") is not None
    return BrowserRuntimeStatus(
        playwright_installed=installed,
        runtime_ready=installed,
        allowed_operations=(
            BrowserRuntimeOperation.NAVIGATE,
            BrowserRuntimeOperation.DOM_SNAPSHOT,
            BrowserRuntimeOperation.SCREENSHOT,
        ),
    )


class BrowserObservation(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: str
    final_url: str
    title: str | None = None
    dom_sha256: str | None = None
    screenshot_sha256: str | None = None
    redirect_observed: bool = False


BrowserDriver = Callable[[str], BrowserObservation]


def execute_browser_observation(target: str, driver: BrowserDriver) -> BrowserObservation:
    observation = driver(target)
    if observation.target != target:
        raise ValueError("browser driver returned evidence for a different target")
    if observation.redirect_observed and observation.final_url != target:
        raise ValueError("redirect requires a separately authorized browser action")
    return observation
