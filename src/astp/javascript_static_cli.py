from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from astp.js_static_analysis import analyze_javascript_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze an already-retrieved JavaScript artifact offline."
    )
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    args = parser.parse_args()

    if not args.artifact.is_file():
        parser.error(f"JavaScript artifact does not exist: {args.artifact}")

    result = analyze_javascript_file(args.artifact)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(result.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    print(f"Artifact SHA-256: {result.artifact_sha256}")
    print(f"Signals: {len(result.signals)}")
    print("Confirmed vulnerabilities: 0")
    print("Network execution: NOT PERFORMED")
    print(f"Written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
