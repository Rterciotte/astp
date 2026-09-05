import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

REQUEST = Path("/run/astp/request.json")
MAX_BYTES = 262144


def _authorized_url(request):
    url = str(request.get("target", "")).strip()
    parsed = urlsplit(url)
    allowed = os.environ.get("ASTP_ALLOWED_TARGET", "").strip()
    if request.get("operation") != "browser.navigate":
        raise SystemExit("operation rejected")
    if parsed.scheme != "http" or parsed.hostname != allowed or parsed.port != 8080:
        raise SystemExit("target rejected")
    if parsed.path not in {"/", "/health", "/large"} or parsed.query or parsed.fragment:
        raise SystemExit("target rejected")
    return url


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    url = _authorized_url(request)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        response = page.goto(url, wait_until="domcontentloaded", timeout=15000)
        title = page.title()
        html = page.content()
        browser.close()
    encoded = html.encode("utf-8", errors="replace")
    limit = min(int(request.get("max_output_bytes", MAX_BYTES)), MAX_BYTES)
    print(
        json.dumps(
            {
                "accepted": True,
                "operation": "browser.navigate",
                "target": url,
                "status": response.status if response else None,
                "title": title,
                "dom": encoded[:limit].decode("utf-8", errors="replace"),
                "output_truncated": len(encoded) > limit,
            }
        )
    )


if __name__ == "__main__":
    main()
