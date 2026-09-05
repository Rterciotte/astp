import json
import os
import subprocess
from pathlib import Path

REQUEST = Path("/run/astp/request.json")
MAX_BYTES = 131072
ALLOWED = {"external.nmap.discovery", "external.nmap.service-light"}


def _target(request):
    target = str(request.get("target", "")).strip()
    allowed = os.environ.get("ASTP_ALLOWED_TARGET", "").strip()
    if not allowed or target != allowed:
        raise SystemExit("target rejected")
    return target


def _bounded(text, limit):
    encoded = text.encode("utf-8", errors="replace")
    limit = min(int(limit), MAX_BYTES)
    return encoded[:limit].decode("utf-8", errors="replace"), len(encoded) > limit


def _qualification_bounded_output(request, target):
    if os.environ.get("ASTP_QUALIFICATION_PROBE", "").strip() != "bounded-output-v1":
        return None
    limit = request.get("max_output_bytes", MAX_BYTES)
    stdout, truncated = _bounded("Q" * 4096, limit)
    return {
        "accepted": True,
        "operation": request.get("operation"),
        "target": target,
        "returncode": 0,
        "stdout": stdout,
        "stderr": "",
        "output_truncated": truncated,
        "qualification_probe": "bounded-output-v1",
        "network_io_performed": False,
    }


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    operation = request.get("operation")
    if operation not in ALLOWED:
        raise SystemExit("operation rejected")
    target = _target(request)
    qualification = _qualification_bounded_output(request, target)
    if qualification is not None:
        print(json.dumps(qualification))
        return
    argv = ["nmap", "-sT", "-Pn", "--max-retries", "1", "--host-timeout", "15s", "-p", "8080"]
    if operation == "external.nmap.service-light":
        argv.append("--version-light")
    argv.append(target)
    completed = subprocess.run(
        argv, capture_output=True, text=True, timeout=30, shell=False, check=False
    )
    limit = request.get("max_output_bytes", MAX_BYTES)
    stdout, stdout_truncated = _bounded(completed.stdout, limit)
    stderr, stderr_truncated = _bounded(completed.stderr, limit)
    print(
        json.dumps(
            {
                "accepted": True,
                "operation": operation,
                "target": target,
                "returncode": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": stdout_truncated or stderr_truncated,
            }
        )
    )


if __name__ == "__main__":
    main()
