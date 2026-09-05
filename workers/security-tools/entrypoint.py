from __future__ import annotations

import json
import sys


def main() -> int:
    # Protocol stub only. Tool binaries are injected by the qualified runtime image later.
    print(json.dumps({"runtime": "security-tools.isolated.v1", "status": "protocol-ready"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
