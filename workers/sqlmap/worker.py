import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

REQUEST = Path("/run/astp/request.json")
MAX_OUTPUT = 262_144
FIELDS = {
    "request_id",
    "permit_id",
    "action_id",
    "engagement_id",
    "operation",
    "target",
    "parameter",
    "method",
    "level",
    "risk",
    "max_requests",
    "timeout_seconds",
}


def main() -> None:
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if set(request) - FIELDS:
        raise SystemExit("unknown/arbitrary request fields rejected")
    if request.get("operation") != "sqlmap.detect-bounded.v1":
        raise SystemExit("operation rejected")
    target = str(request.get("target", ""))
    if target != os.environ.get("ASTP_ALLOWED_TARGET"):
        raise SystemExit("exact target binding rejected")
    parameter = str(request.get("parameter", ""))
    if parameter not in parse_qs(urlsplit(target).query, keep_blank_values=True):
        raise SystemExit("exact parameter binding rejected")
    if request.get("method", "GET") != "GET":
        raise SystemExit("method rejected")
    if os.environ.get("ASTP_PERMIT_CONSUMED") != "true":
        raise SystemExit("permit must be consumed before I/O")
    level = max(1, min(int(request.get("level", 1)), 2))
    risk = max(1, min(int(request.get("risk", 1)), 1))
    timeout = max(10, min(int(request.get("timeout_seconds", 30)), 60))
    max_requests = max(1, min(int(request.get("max_requests", 50)), 100))
    proxy = os.environ.get("ASTP_PROXY_URL", "")
    if not proxy.startswith("http://"):
        raise SystemExit("ASTP counting proxy is required")
    argv = [
        "python",
        "/opt/sqlmap/sqlmap.py",
        "-u",
        target,
        "-p",
        parameter,
        "--method=GET",
        f"--level={level}",
        f"--risk={risk}",
        "--batch",
        "--answers=exploit=N",
        "--smart",
        "--flush-session",
        "--technique=B",
        "--timeout=5",
        "--retries=0",
        "--threads=1",
        f"--proxy={proxy}",
        "--output-dir=/tmp/sqlmap",
    ]
    completed = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    raw = completed.stdout + completed.stderr
    output = raw[:MAX_OUTPUT]
    decoded = raw.decode(errors="replace")
    request_match = re.search(r"total of (\d+) HTTP\(s\) requests", decoded)
    requests_accounted = int(request_match.group(1)) if request_match else None
    detected = "is vulnerable" in decoded and "injectable" in decoded
    accepted = (
        completed.returncode == 0
        and detected
        and requests_accounted is not None
        and requests_accounted <= max_requests
    )
    print(
        json.dumps(
            {
                "accepted": accepted,
                "operation": request["operation"],
                "target": target,
                "parameter": parameter,
                "returncode": completed.returncode,
                "output": output.decode(errors="replace"),
                "output_sha256": hashlib.sha256(output).hexdigest(),
                "output_truncated": len(raw) > MAX_OUTPUT,
                "permit_consumed_before_io": True,
                "network_io_performed": True,
                "requests_accounted": requests_accounted,
                "max_requests": max_requests,
                "detected": detected,
                "post_exploitation_performed": False,
                "tool_version": "1.9.9",
                "argv_contract": "typed:sqlmap.detect-bounded.v1",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
