import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

REQUEST = Path("/run/astp/request.json")
MAX_BYTES = 131072


def _authorized_url(request):
    url = str(request.get("target", "")).strip()
    parsed = urlsplit(url)
    allowed = os.environ.get("ASTP_ALLOWED_TARGET", "").strip()
    if request.get("operation") != "external.zap.baseline":
        raise SystemExit("operation rejected")
    if parsed.scheme != "http" or parsed.hostname != allowed or parsed.port != 8080:
        raise SystemExit("target rejected")
    if parsed.path not in {"/", "/health", "/large"} or parsed.query or parsed.fragment:
        raise SystemExit("target rejected")
    return url


def _bounded(text, limit):
    encoded = text.encode("utf-8", errors="replace")
    limit = min(int(limit), MAX_BYTES)
    return encoded[:limit].decode("utf-8", errors="replace"), len(encoded) > limit


def _qualification_bounded_output(request, url):
    if os.environ.get("ASTP_QUALIFICATION_PROBE", "").strip() != "bounded-output-v1":
        return None
    limit = request.get("max_output_bytes", MAX_BYTES)
    stdout, truncated = _bounded("Q" * 4096, limit)
    return {
        "accepted": True,
        "operation": "external.zap.baseline",
        "target": url,
        "returncode": 0,
        "stdout": stdout,
        "stderr": "",
        "output_truncated": truncated,
        "qualification_probe": "bounded-output-v1",
        "network_io_performed": False,
    }


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    url = _authorized_url(request)
    qualification = _qualification_bounded_output(request, url)
    if qualification is not None:
        print(json.dumps(qualification))
        return
    argv = ["zap-baseline.py", "-t", url, "-I", "-m", "1", "-d"]
    completed = subprocess.run(
        argv, capture_output=True, text=True, timeout=90, shell=False, check=False
    )
    stdout, stdout_truncated = _bounded(
        completed.stdout, request.get("max_output_bytes", MAX_BYTES)
    )
    stderr, stderr_truncated = _bounded(
        completed.stderr, request.get("max_output_bytes", MAX_BYTES)
    )
    print(
        json.dumps(
            {
                "accepted": True,
                "operation": "external.zap.baseline",
                "target": url,
                "returncode": completed.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": stdout_truncated or stderr_truncated,
            }
        )
    )


if __name__ == "__main__":
    main()
