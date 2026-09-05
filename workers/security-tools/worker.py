import json
from pathlib import Path

REQUEST = Path("/run/astp/request.json")
ALLOWED = {"external.nmap.discovery", "external.nmap.service-light"}


def main():
    request = json.loads(REQUEST.read_text(encoding="utf-8"))
    if request.get("operation") not in ALLOWED:
        raise SystemExit("operation rejected")
    print(json.dumps({"accepted": True, "operation": request["operation"]}))


if __name__ == "__main__":
    main()
