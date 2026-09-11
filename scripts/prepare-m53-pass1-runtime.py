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
        proxy_image_digest="sha256:359f7b593714ccbe692f16b9127b771cd5d6e272f52037e8e5663aa0b98f0589",
        runtimes={
            "nuclei.astp-lab-cve.v1": DockerDetectorRuntime(
                image="astp/nuclei-worker:m52",
                image_digest="sha256:8074909a9b3bf948c9b75103df1367690b8bb0a039e4658e6616aea4205d3459",
            ),
            "ffuf.discovery-bounded.v1": DockerDetectorRuntime(
                image="astp/ffuf-worker:m52",
                image_digest="sha256:0ca90ed6786042fd13735b0bd7dfa2d9a793846fdf78c226071ad21f20b51dfa",
            ),
            "dalfox.reflected-bounded.v1": DockerDetectorRuntime(
                image="astp/dalfox-worker:m52",
                image_digest="sha256:4598aeb2403c27d5ecda7c9a853d88df255a2874e4cc772bfa33bcb88aa16afc",
            ),
            "playwright.dom-navigation-field.v1": DockerDetectorRuntime(
                image="astp/playwright-field-worker:m52",
                image_digest="sha256:40aa366c13c49219029f280bb446990f9bcec3e88f768fee41deb61f73a44fb4",
            ),
            "sqlmap.detect-bounded.v1": DockerDetectorRuntime(
                image="astp/sqlmap-worker:m52",
                image_digest="sha256:ca2886211f38fef3858d37e4f22a33c22051487d1872216efcccb53de15dbd16",
            ),
        },
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(config.model_dump_json(indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
