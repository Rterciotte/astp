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
    if request.get("operation") != "external.zap.passive-baseline":
        raise SystemExit("operation rejected")
    if parsed.scheme != "http" or parsed.hostname != allowed or parsed.port != 8080:
        raise SystemExit("target rejected")
    if parsed.path not in {"/", "/health"} or parsed.query or parsed.fragment:
        raise SystemExit("target rejected")
    return url


def _bounded(text):
    encoded = text.encode("utf-8", errors="replace")
    return encoded[:MAX_BYTES].decode("utf-8", errors="replace"), len(encoded) > MAX_BYTES


def main():
    url = _authorized_url(json.loads(REQUEST.read_text(encoding="utf-8")))
    argv = ["zap-baseline.py", "-t", url, "-I", "-m", "1", "-d"]
    completed = subprocess.run(
        argv, capture_output=True, text=True, timeout=90, shell=False, check=False
    )
    stdout, stdout_truncated = _bounded(completed.stdout)
    stderr, stderr_truncated = _bounded(completed.stderr)
    print(
        json.dumps(
            {
                "accepted": True,
                "operation": "external.zap.passive-baseline",
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
