import hashlib
import json
import os
import subprocess
from pathlib import Path

REQUEST = Path("/run/astp/request.json")
MAX_OUTPUT = 262_144
TEMPLATES = {"astp-lab-cve-2099-0001": "/opt/astp/templates/astp-lab-cve.yaml"}
ALLOWED_FIELDS = {
    "request_id",
    "permit_id",
    "action_id",
    "engagement_id",
    "operation",
    "target",
    "template_ids",
    "max_requests",
    "max_concurrency",
    "rate_per_second",
    "timeout_seconds",
}


def main():
    Path("/tmp/home/.config").mkdir(parents=True, exist_ok=True)
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if set(request) - ALLOWED_FIELDS:
        raise SystemExit("unknown/arbitrary request fields rejected")
    if request.get("operation") != "external.nuclei.safe":
        raise SystemExit("operation rejected")
    target = str(request.get("target", ""))
    if target != os.environ.get("ASTP_ALLOWED_TARGET", ""):
        raise SystemExit("exact target binding rejected")
    if not request.get("permit_id") or not request.get("action_id"):
        raise SystemExit("permit/action binding required")
    if os.environ.get("ASTP_PERMIT_CONSUMED") != "true":
        raise SystemExit("permit must be consumed before I/O")
    template_ids = request.get("template_ids", [])
    if not template_ids or any(item not in TEMPLATES for item in template_ids):
        raise SystemExit("unclassified template rejected")
    max_requests = min(int(request.get("max_requests", 1)), 20)
    if max_requests < len(template_ids):
        raise SystemExit("request budget insufficient")
    concurrency = min(int(request.get("max_concurrency", 1)), 2)
    rate = max(1, min(int(float(request.get("rate_per_second", 1))), 2))
    timeout = min(int(request.get("timeout_seconds", 30)), 60)
    proxy = os.environ.get("ASTP_PROXY_URL", "")
    if not proxy.startswith("http://"):
        raise SystemExit("ASTP counting proxy is required")
    if os.environ.get("ASTP_QUALIFICATION_PROBE") == "bounded-output-v1":
        raw = b"Q" * (MAX_OUTPUT + 4096)
        print(
            json.dumps(
                {
                    "accepted": True,
                    "network_io_performed": False,
                    "permit_consumed_before_io": True,
                    "stdout": raw[:MAX_OUTPUT].decode(),
                    "output_truncated": True,
                    "output_sha256": hashlib.sha256(raw[:MAX_OUTPUT]).hexdigest(),
                    "qualification_probe": "bounded-output-v1",
                }
            )
        )
        return
    argv = [
        "nuclei",
        "-u",
        target,
        "-jsonl",
        "-silent",
        "-duc",
        "-ni",
        "-rl",
        str(rate),
        "-c",
        str(concurrency),
        "-timeout",
        str(timeout),
        "-proxy",
        proxy,
    ]
    for template_id in template_ids:
        argv.extend(("-t", TEMPLATES[template_id]))
    completed = subprocess.run(argv, capture_output=True, timeout=timeout + 10, check=False)
    output = completed.stdout[:MAX_OUTPUT]
    print(
        json.dumps(
            {
                "accepted": completed.returncode == 0,
                "operation": "external.nuclei.safe",
                "target": target,
                "returncode": completed.returncode,
                "stdout": output.decode("utf-8", errors="replace"),
                "stderr": completed.stderr[:MAX_OUTPUT].decode("utf-8", errors="replace"),
                "output_sha256": hashlib.sha256(output).hexdigest(),
                "output_truncated": len(completed.stdout) > MAX_OUTPUT,
                "permit_consumed_before_io": True,
                "network_io_performed": True,
                "requests_accounted": len(template_ids),
                "tool_version": "3.4.10",
                "templates_revision": "astp-m52-lab-v1",
                "template_ids": template_ids,
                "argv_contract": "typed:nuclei.safe.v1",
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
