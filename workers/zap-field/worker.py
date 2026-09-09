import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import quote, urlsplit
from urllib.request import urlopen

REQUEST = Path("/run/astp/request.json")
MAX_OUTPUT = 262_144
ALLOWED = {
    "request_id",
    "permit_id",
    "action_id",
    "engagement_id",
    "operation",
    "target",
    "max_urls",
    "max_duration_seconds",
    "rate_per_second",
    "timeout_seconds",
}


def api(path: str, timeout: float = 3) -> dict:
    with urlopen("http://127.0.0.1:8090" + path, timeout=timeout) as response:
        return json.loads(response.read(MAX_OUTPUT))


def main() -> None:
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if set(request) - ALLOWED:
        raise SystemExit("unknown/arbitrary request fields rejected")
    if request.get("operation") != "external.zap.passive-field":
        raise SystemExit("operation rejected")
    target = str(request.get("target", ""))
    parsed = urlsplit(target)
    if target != os.environ.get("ASTP_ALLOWED_TARGET") or parsed.scheme not in {"http", "https"}:
        raise SystemExit("exact target binding rejected")
    if not request.get("permit_id") or not request.get("action_id"):
        raise SystemExit("permit/action binding required")
    if os.environ.get("ASTP_PERMIT_CONSUMED") != "true":
        raise SystemExit("permit must be consumed before I/O")
    proxy = urlsplit(os.environ.get("ASTP_PROXY_URL", ""))
    if proxy.scheme != "http" or not proxy.hostname or not proxy.port:
        raise SystemExit("ASTP counting proxy is required")
    duration = max(10, min(int(request.get("max_duration_seconds", 45)), 60))
    max_urls = max(1, min(int(request.get("max_urls", 1)), 10))
    argv = [
        "/zap/zap.sh",
        "-daemon",
        "-host",
        "127.0.0.1",
        "-port",
        "8090",
        "-config",
        "api.disablekey=true",
        "-config",
        "ascan.disabled=true",
        "-config",
        "connection.proxyChain.enabled=true",
        "-config",
        f"connection.proxyChain.hostName={proxy.hostname}",
        "-config",
        f"connection.proxyChain.port={proxy.port}",
    ]
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    try:
        while True:
            if process.poll() is not None:
                raise RuntimeError("ZAP daemon exited during startup")
            try:
                api("/JSON/core/view/version/")
                break
            except OSError:
                if time.monotonic() - started >= min(duration, 45):
                    raise TimeoutError("ZAP daemon startup timed out")
                time.sleep(0.25)
        api(f"/JSON/core/action/accessUrl/?url={quote(target, safe='')}&followRedirects=false")
        while time.monotonic() - started < duration:
            remaining = int(api("/JSON/pscan/view/recordsToScan/").get("recordsToScan", 0))
            if remaining == 0:
                break
            time.sleep(0.25)
        else:
            raise TimeoutError("ZAP passive scan timed out")
        sites = api("/JSON/core/view/sites/").get("sites", [])[:max_urls]
        alerts = api(f"/JSON/core/view/alerts/?baseurl={quote(target, safe='')}").get("alerts", [])
        report = json.dumps({"sites": sites, "alerts": alerts}, sort_keys=True).encode()
        bounded = report[:MAX_OUTPUT]
        print(
            json.dumps(
                {
                    "accepted": True,
                    "operation": request["operation"],
                    "target": target,
                    "structured_report": json.loads(bounded),
                    "output_sha256": hashlib.sha256(bounded).hexdigest(),
                    "output_truncated": len(report) > MAX_OUTPUT,
                    "permit_consumed_before_io": True,
                    "network_io_performed": True,
                    "requests_accounted": None,
                    "accounting_source": "ASTP counting proxy receipt required",
                    "passive_only": True,
                    "max_urls": max_urls,
                    "max_duration_seconds": duration,
                },
                sort_keys=True,
            )
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    main()
