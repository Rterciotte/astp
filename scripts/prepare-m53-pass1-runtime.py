from __future__ import annotations

import argparse
from pathlib import Path

from astp.docker_detector_adapter import DockerDetectorConfig, DockerDetectorRuntime


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-network", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    config = DockerDetectorConfig(
        target_network=arguments.target_network,
        runtimes={
            "nuclei.astp-lab-cve.v1": DockerDetectorRuntime(
                image="astp/nuclei-worker:m52",
                image_digest="sha256:8074909a9b3bf948c9b75103df1367690b8bb0a039e4658e6616aea4205d3459",
            ),
            "ffuf.discovery-bounded.v1": DockerDetectorRuntime(
                image="astp/ffuf-worker:m52",
                image_digest="sha256:0ca90ed6786042fd13735b0bd7dfa2d9a793846fdf78c226071ad21f20b51dfa",
            ),
        },
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(config.model_dump_json(indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
