from __future__ import annotations

import json


def main() -> None:
    print(
        json.dumps(
            {
                "runtime_id": "playwright.isolated.v1",
                "ready": False,
                "reason": "protocol stub; not field-qualified",
            }
        )
    )


if __name__ == "__main__":
    main()
