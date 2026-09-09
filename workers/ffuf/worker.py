import hashlib
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

REQUEST = Path("/run/astp/request.json")
MAX_OUTPUT = 262_144
WORDS = ("admin", ".astp-hidden", "health", "api")
FIELDS = {
    "request_id",
    "permit_id",
    "action_id",
    "engagement_id",
    "operation",
    "origin",
    "max_words",
    "max_requests",
    "concurrency",
    "rate_per_second",
    "timeout_seconds",
}


def main() -> None:
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if set(request) - FIELDS:
        raise SystemExit("unknown/arbitrary request fields rejected")
    if request.get("operation") != "ffuf.discovery-bounded.v1":
        raise SystemExit("operation rejected")
    origin = str(request.get("origin", "")).rstrip("/")
    parsed = urlsplit(origin)
    if origin != os.environ.get("ASTP_ALLOWED_ORIGIN", "").rstrip("/") or parsed.path not in {
        "",
        "/",
    }:
        raise SystemExit("exact origin binding rejected")
    if os.environ.get("ASTP_PERMIT_CONSUMED") != "true":
        raise SystemExit("permit must be consumed before I/O")
    count = max(1, min(int(request.get("max_words", 4)), len(WORDS)))
    if int(request.get("max_requests", count)) < count:
        raise SystemExit("request budget insufficient")
    wordlist = Path("/tmp/words.txt")
    wordlist.write_text("\n".join(WORDS[:count]) + "\n", encoding="utf-8")
    concurrency = max(1, min(int(request.get("concurrency", 1)), 2))
    rate = max(1, min(int(request.get("rate_per_second", 1)), 2))
    timeout = max(5, min(int(request.get("timeout_seconds", 20)), 60))
    proxy = os.environ.get("ASTP_PROXY_URL", "")
    if not proxy.startswith("http://"):
        raise SystemExit("ASTP counting proxy is required")
    argv = [
        "ffuf",
        "-u",
        f"{origin}/FUZZ",
        "-w",
        str(wordlist),
        "-json",
        "-noninteractive",
        "-recursion=false",
        "-scrapers",
        "none",
        "-t",
        str(concurrency),
        "-rate",
        str(rate),
        "-timeout",
        "5",
        "-x",
        proxy,
        "-mc",
        "all",
    ]
    completed = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    output = completed.stdout[:MAX_OUTPUT]
    print(
        json.dumps(
            {
                "accepted": completed.returncode == 0,
                "operation": request["operation"],
                "origin": origin,
                "returncode": completed.returncode,
                "stdout": output.decode(errors="replace"),
                "stderr": completed.stderr[-8192:].decode(errors="replace"),
                "output_sha256": hashlib.sha256(output).hexdigest(),
                "output_truncated": len(completed.stdout) > MAX_OUTPUT,
                "permit_consumed_before_io": True,
                "network_io_performed": True,
                "requests_accounted": count,
                "tool_version": "2.1.0",
                "wordlist_revision": "astp-m52-v1",
                "recursion": False,
                "argv_contract": "typed:ffuf.discovery-bounded.v1",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
