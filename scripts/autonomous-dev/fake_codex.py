from __future__ import annotations

import os
import sys
import time

mode = os.environ.get("ASTP_FAKE_CODEX_MODE", "MILESTONE_COMPLETE")
_ = sys.stdin.read()
if mode == "CRASH":
    raise SystemExit(17)
if mode == "TIMEOUT":
    time.sleep(60)
if mode == "MALFORMED":
    print("unstructured result")
    raise SystemExit(0)
if mode == "GENERIC_ERROR":
    print("generic local failure", file=sys.stderr)
    raise SystemExit(2)
if mode == "USAGE_TEXT":
    print("Codex usage limit reached", file=sys.stderr)
    raise SystemExit(1)
print(f"ASTP_AUTODEV_RESULT={mode}")
