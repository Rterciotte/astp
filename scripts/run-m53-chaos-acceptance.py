from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from astp.m53_chaos import ChaosPoint, verify_chaos_manifest


def run(argv: list[str], expected: int = 0) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    if completed.returncode != expected:
        raise RuntimeError(
            f"command returned {completed.returncode}, expected {expected}: {completed.stderr}"
        )
    return completed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--campaign-id", default="m53-pass2-chaos")
    parser.add_argument("--target", required=True)
    arguments = parser.parse_args()
    arguments.root.mkdir(parents=True, exist_ok=True)
    for index, point in enumerate(ChaosPoint, 1):
        point_root = arguments.root / f"point-{index}"
        base = [
            sys.executable,
            "-m",
            "astp.cli",
            "orchestrator-chaos-inject",
            "--campaign-id",
            arguments.campaign_id,
            "--point",
            point.value,
            "--root",
            str(point_root),
            "--target",
            arguments.target,
            "--acceptance-enabled",
        ]
        run(base, expected=86)
        run(
            [
                sys.executable,
                "-m",
                "astp.cli",
                "orchestrator-chaos-resume",
                "--campaign-id",
                arguments.campaign_id,
                "--root",
                str(point_root),
            ]
        )
    consolidate = [
        sys.executable,
        "-m",
        "astp.cli",
        "orchestrator-chaos-consolidate",
        "--campaign-id",
        arguments.campaign_id,
        "--root",
        str(arguments.root),
    ]
    run(consolidate)
    first = json.loads((arguments.root / "chaos-report.json").read_text())
    run(consolidate)
    second = json.loads((arguments.root / "chaos-report.json").read_text())
    if first != second or not verify_chaos_manifest(arguments.root):
        raise RuntimeError("report or manifest regeneration is not idempotent")
    if first["chaos_points_passed"] != 8 or first["chaos_points_failed"] != 0:
        raise RuntimeError("physical chaos matrix did not pass 8/8")
    print(json.dumps(first, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
