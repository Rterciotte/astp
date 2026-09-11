from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from astp.browser_intake import BrowserCapture
from astp.detector_registry import builtin_detector_registry
from astp.docker_detector_adapter import (
    DockerDetectorAdapter,
    DockerDetectorConfig,
    DockerDetectorRuntime,
)
from astp.m53_auth_chain import derive_local_authorized_detector_request
from astp.orchestrator import run_orchestrator_execution
from astp.orchestrator_models import AutonomousCampaignConfig


def _captures(now: datetime) -> tuple[BrowserCapture, BrowserCapture]:
    detail_url = "http://local-bughunt.test/program/detail?id=local-m52"
    return (
        BrowserCapture(
            url="http://local-bughunt.test/programs",
            text="Programas timeline\nMostrando 1 programa\nPublicado há 1 minuto",
            links=[{"text": "Local M52", "href": detail_url}],
            captured_at=now,
        ),
        BrowserCapture(
            url=detail_url,
            title="Local M52",
            text="""
Política do programa
Lista de escopo do programa
## Escopo
- http://astp-m52-lab:8080/
É proibido realizar ataques quando o programa estiver offline.
Recomendamos o User Agent: ASTP local acceptance.
""",
            captured_at=now,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-network", required=True)
    parser.add_argument("--runtime-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-cli-inputs", action="store_true")
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    detector = next(
        item for item in builtin_detector_registry() if item.detector_id == "nuclei.astp-lab-cve.v1"
    )
    key = "astp-local-signing-key-must-be-32-bytes-long"
    now = datetime.now(UTC)
    listing, detail = _captures(now)
    request, broker = derive_local_authorized_detector_request(
        root=arguments.output / "authorization-chain",
        campaign_id="physical-service-1",
        listing_capture=listing,
        detail_capture=detail,
        target="http://astp-m52-lab:8080/",
        detector=detector,
        runtime_digest=arguments.runtime_digest,
        signing_key=key,
        now=now,
    )
    adapter_config = DockerDetectorConfig(
        target_network=arguments.target_network,
        proxy_image_digest="sha256:667244c6e1a89371dc227aa6a6bd73e71f8fad8f8521911f83c680c481279f13",
        runtimes={
            detector.detector_id: DockerDetectorRuntime(
                image="astp/nuclei-worker:m52", image_digest=arguments.runtime_digest
            )
        },
        timeout_seconds=30,
    )
    if arguments.prepare_cli_inputs:
        (arguments.output / "docker-config.json").write_text(
            adapter_config.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (arguments.output / "detector-request.json").write_text(
            request.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"prepared": True, "permit_id": broker.permit.payload.permit_id}))
        return 0

    adapter = DockerDetectorAdapter(adapter_config, key)
    snapshot, results = run_orchestrator_execution(
        AutonomousCampaignConfig(
            campaign_id="physical-service-1",
            selected_program_ids=(request.program_id,),
            dry_run=False,
            execute=True,
        ),
        arguments.output / "orchestrator",
        requests=(request,),
        adapters=(adapter,),
        signing_key=key,
    )
    result = results[0]
    print(result.model_dump_json(indent=2))
    print(json.dumps(snapshot, default=str))
    return 0 if result.status == "completed" and result.accounting.forwarded > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
