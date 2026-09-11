from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from astp.m53_chaos import (
    ChaosPoint,
    consolidate_chaos,
    reconstruct_physical_completion,
    verify_chaos_manifest,
)


def run(argv: list[str], expected: int = 0) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["ASTP_ACCEPTANCE_MODE"] = "local-only"
    completed = subprocess.run(argv, capture_output=True, text=True, check=False, env=environment)
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
    parser.add_argument("--target-network", required=True)
    parser.add_argument("--runtime-digest", required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--proxy-digest", required=True)
    arguments = parser.parse_args()
    arguments.root.mkdir(parents=True, exist_ok=True)
    physical_faults = {
        ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH: "before_worker_launch",
        ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO: (
            "after_worker_launch_before_first_io"
        ),
        ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN: (
            "after_first_proxy_forward"
        ),
        ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST: (
            "after_proxy_result_before_evidence_normalization"
        ),
        ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF: ("after_evidence_normalization_before_persistence"),
        ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN: "worker_crash_after_target_response",
    }
    for index, point in enumerate(ChaosPoint, 1):
        point_root = arguments.root / f"point-{index}"
        if point in physical_faults:
            run(
                [
                    sys.executable,
                    "scripts/run-m52-detector-service-acceptance.py",
                    "--campaign-id",
                    f"{arguments.campaign_id}-{index}",
                    "--target-network",
                    arguments.target_network,
                    "--runtime-digest",
                    arguments.runtime_digest,
                    "--proxy-image",
                    arguments.proxy_image,
                    "--proxy-digest",
                    arguments.proxy_digest,
                    "--output",
                    str(point_root),
                    "--fault",
                    physical_faults[point],
                ]
            )
            continue
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
    completion_root = arguments.root / "completed-physical-run"
    run(
        [
            sys.executable,
            "scripts/run-m52-detector-service-acceptance.py",
            "--campaign-id",
            f"{arguments.campaign_id}-completed",
            "--target-network",
            arguments.target_network,
            "--runtime-digest",
            arguments.runtime_digest,
            "--proxy-image",
            arguments.proxy_image,
            "--proxy-digest",
            arguments.proxy_digest,
            "--output",
            str(completion_root),
        ]
    )
    reconstructed = reconstruct_physical_completion(completion_root)
    if reconstructed["network_replayed"] or reconstructed["proof_state"] == "observed":
        raise RuntimeError("physical proof reconstruction did not advance from durable evidence")
    containers = run(
        [
            "docker",
            "ps",
            "--all",
            "--format",
            "{{.Names}}",
            "--filter",
            "name=astp-worker-",
            "--filter",
            "name=astp-proxy-",
        ]
    ).stdout.splitlines()
    if containers:
        raise RuntimeError(f"orphan acceptance containers remain: {containers}")
    lifecycle_files = list(arguments.root.glob("point-*/**/worker-lifecycle.json"))
    if not lifecycle_files or any(
        json.loads(path.read_text(encoding="utf-8")).get("direct_target_network_attached")
        is not False
        for path in lifecycle_files
    ):
        raise RuntimeError("independent worker network-isolation oracle failed")
    (arguments.root / "independent-oracles.json").write_text(
        json.dumps(
            {
                "orphan_acceptance_containers": containers,
                "direct_target_network_attachments": 0,
                "physical_completion_reopened": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    consolidate_chaos(arguments.root, arguments.campaign_id)
    first = json.loads((arguments.root / "chaos-report.json").read_text())
    consolidate_chaos(arguments.root, arguments.campaign_id)
    second = json.loads((arguments.root / "chaos-report.json").read_text())
    if first != second or not verify_chaos_manifest(arguments.root):
        raise RuntimeError("report or manifest regeneration is not idempotent")
    if first["chaos_points_passed"] != 8 or first["chaos_points_failed"] != 0:
        raise RuntimeError("physical chaos matrix did not pass 8/8")
    print(json.dumps(first, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
