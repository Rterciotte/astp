import hashlib
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

REQUEST = Path("/run/astp/request.json")
MAX_OUTPUT = 262_144
OPERATIONS = {
    "dalfox.parameter-preflight",
    "dalfox.reflected-bounded",
    "dalfox.dom-analysis",
}
FIELDS = {
    "request_id",
    "permit_id",
    "action_id",
    "engagement_id",
    "operation",
    "target",
    "parameter",
    "max_requests",
    "max_workers",
    "rate_per_second",
    "timeout_seconds",
}


def main() -> None:
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if set(request) - FIELDS:
        raise SystemExit("unknown/arbitrary request fields rejected")
    operation = request.get("operation")
    if operation not in OPERATIONS:
        raise SystemExit("operation rejected")
    target = str(request.get("target", ""))
    parsed = urlsplit(target)
    if target != os.environ.get("ASTP_ALLOWED_TARGET") or parsed.scheme not in {"http", "https"}:
        raise SystemExit("exact target binding rejected")
    parameter = str(request.get("parameter", ""))
    if not parameter or parameter not in parse_qs(parsed.query, keep_blank_values=True):
        raise SystemExit("exact parameter binding rejected")
    if not request.get("permit_id") or not request.get("action_id"):
        raise SystemExit("permit/action binding required")
    if os.environ.get("ASTP_PERMIT_CONSUMED") != "true":
        raise SystemExit("permit must be consumed before I/O")
    workers = max(1, min(int(request.get("max_workers", 1)), 2))
    rate = max(1, min(int(request.get("rate_per_second", 1)), 2))
    timeout = max(5, min(int(request.get("timeout_seconds", 30)), 60))
    proxy = os.environ.get("ASTP_PROXY_URL", "")
    if not proxy.startswith("http://"):
        raise SystemExit("ASTP counting proxy is required")
    argv = [
        "dalfox",
        "url",
        target,
        "--param",
        parameter,
        "--worker",
        str(workers),
        "--delay",
        str(1000 // rate),
        "--timeout",
        "5",
        "--format",
        "jsonl",
        "--no-color",
        "--no-spinner",
        "--skip-bav",
        "--skip-mining-all",
        "--proxy",
        proxy,
    ]
    if operation == "dalfox.parameter-preflight":
        argv.append("--only-discovery")
    elif operation == "dalfox.reflected-bounded":
        argv.extend(
            (
                "--custom-payload",
                "/opt/astp/reflected-payloads.txt",
                "--only-custom-payload",
            )
        )
    if operation != "dalfox.dom-analysis":
        argv.append("--skip-headless")
    completed = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    output = completed.stdout[:MAX_OUTPUT]
    print(
        json.dumps(
            {
                "accepted": completed.returncode == 0,
                "operation": operation,
                "target": target,
                "parameter": parameter,
                "returncode": completed.returncode,
                "stdout": output.decode(errors="replace"),
                "stderr": completed.stderr[-8192:].decode(errors="replace"),
                "output_sha256": hashlib.sha256(output).hexdigest(),
                "output_truncated": len(completed.stdout) > MAX_OUTPUT,
                "permit_consumed_before_io": True,
                "network_io_performed": True,
                "requests_accounted": None,
                "accounting_limitation": "Dalfox does not expose exact request count",
                "tool_version": "2.12.0",
                "argv_contract": "typed:dalfox.v1",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
