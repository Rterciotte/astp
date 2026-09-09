import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

REQUEST = Path("/run/astp/request.json")
MAX_OUTPUT = 262_144
ALLOWED = {
    "request_id",
    "permit_id",
    "action_id",
    "engagement_id",
    "operation",
    "target",
    "timeout_seconds",
    "identity_ref",
    "profile",
}


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if set(request) - ALLOWED:
        raise SystemExit("unknown/arbitrary request fields rejected")
    if request.get("operation") != "browser.field-navigate":
        raise SystemExit("operation rejected")
    target = str(request.get("target", ""))
    allowed = os.environ.get("ASTP_ALLOWED_TARGET", "")
    if target != allowed:
        raise SystemExit("exact target binding rejected")
    if os.environ.get("ASTP_PERMIT_CONSUMED") != "true":
        raise SystemExit("permit must be consumed before I/O")
    origin = lambda value: (
        urlsplit(value).scheme,
        urlsplit(value).hostname,
        urlsplit(value).port or (443 if urlsplit(value).scheme == "https" else 80),
    )
    timeout = min(int(request.get("timeout_seconds", 30)), 60) * 1000
    proxy = os.environ.get("ASTP_PROXY_URL", "")
    if not proxy.startswith("http://"):
        raise SystemExit("ASTP counting proxy is required")
    with sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=True, proxy={"server": proxy})
        page = browser.new_page()
        response = page.goto(target, wait_until="domcontentloaded", timeout=timeout)
        final = page.url
        if origin(final) != origin(target):
            browser.close()
            raise SystemExit("cross-origin redirect rejected")
        dom = page.content().encode()
        title = page.title()
        browser.close()
    bounded = dom[:MAX_OUTPUT]
    print(
        json.dumps(
            {
                "accepted": True,
                "operation": request["operation"],
                "target": target,
                "final_url": final,
                "status": response.status if response else None,
                "title": title,
                "dom": bounded.decode(errors="replace"),
                "output_sha256": hashlib.sha256(bounded).hexdigest(),
                "output_truncated": len(dom) > MAX_OUTPUT,
                "permit_consumed_before_io": True,
                "network_io_performed": True,
                "requests_accounted": 1,
                "identity_ref": request.get("identity_ref"),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
