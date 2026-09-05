import json
from pathlib import Path

REQUEST = Path("/run/astp/request.json")
MAX_BYTES = 262144


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if request.get("operation") not in {"browser.observe"}:
        raise SystemExit("operation rejected")
    # Physical navigation remains owned by the permit-consuming host bridge.
    print(
        json.dumps(
            {"accepted": True, "operation": request["operation"], "max_output_bytes": MAX_BYTES}
        )
    )


if __name__ == "__main__":
    main()
