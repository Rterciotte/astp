from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict

from astp.browser_runtime import BrowserObservation


class BrowserWorkerJob(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    target: str
    permit_id: str
    action_id: str
    operation: str = "browser.navigate"


PermitConsumer = Callable[[str, str], None]
BrowserDriver = Callable[[str], BrowserObservation]


def execute_permit_consumed_browser(
    job: BrowserWorkerJob,
    *,
    consume: PermitConsumer,
    driver: BrowserDriver,
) -> BrowserObservation:
    if job.operation not in {"browser.navigate", "browser.dom_snapshot", "browser.screenshot"}:
        raise ValueError("browser operation is outside the bounded observation set")
    consume(job.permit_id, job.action_id)
    result = driver(job.target)
    if result.target != job.target:
        raise ValueError("browser evidence target does not match authorized target")
    if result.redirect_observed and result.final_url != job.target:
        raise ValueError("browser redirect requires a new authorization and permit")
    return result
