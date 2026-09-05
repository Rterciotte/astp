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


def _bounded(text):
    encoded = text.encode("utf-8", errors="replace")
    return encoded[:MAX_BYTES].decode("utf-8", errors="replace"), len(encoded) > MAX_BYTES


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    operation = request.get("operation")
    if operation not in ALLOWED:
        raise SystemExit("operation rejected")
    target = _target(request)
    argv = ["nmap", "-sT", "-Pn", "--max-retries", "1", "--host-timeout", "15s", "-p", "8080"]
    if operation == "external.nmap.service-light":
        argv.append("--version-light")
    argv.append(target)
    completed = subprocess.run(
        argv, capture_output=True, text=True, timeout=30, shell=False, check=False
    )
    stdout, stdout_truncated = _bounded(completed.stdout)
    stderr, stderr_truncated = _bounded(completed.stderr)
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
