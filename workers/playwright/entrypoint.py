from __future__ import annotations

import json
import sys


def main() -> int:
    # Protocol stub only. The host supervisor must consume an exact permit before launch.
    print(json.dumps({"runtime": "playwright.isolated.v1", "status": "protocol-ready"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
