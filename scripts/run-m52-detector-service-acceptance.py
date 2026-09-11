from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from astp.browser_intake import BrowserCapture
from astp.detector_execution import DetectorExecutionService
from astp.detector_registry import builtin_detector_registry
from astp.docker_detector_adapter import (
    DockerDetectorAdapter,
    DockerDetectorConfig,
    DockerDetectorRuntime,
    DockerLifecycleFaultPoint,
)
from astp.m53_auth_chain import derive_local_authorized_detector_request
from astp.m53_chaos import ChaosPoint, recover_physical_detector_chaos
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
    parser.add_argument("--campaign-id", default="physical-service-1")
    parser.add_argument("--runtime-digest", required=True)
    parser.add_argument(
        "--proxy-digest",
        default="sha256:359f7b593714ccbe692f16b9127b771cd5d6e272f52037e8e5663aa0b98f0589",
    )
    parser.add_argument("--proxy-image", default="astp/counting-proxy:m52")
    parser.add_argument("--fault", choices=[point.value for point in DockerLifecycleFaultPoint])
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
        campaign_id=arguments.campaign_id,
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
        proxy_image=arguments.proxy_image,
        proxy_image_digest=arguments.proxy_digest,
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

    fault = DockerLifecycleFaultPoint(arguments.fault) if arguments.fault else None
    adapter = DockerDetectorAdapter(adapter_config, key, acceptance_fault=fault)
    snapshot, results = run_orchestrator_execution(
        AutonomousCampaignConfig(
            campaign_id=arguments.campaign_id,
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
    chaos_points = {
        DockerLifecycleFaultPoint.BEFORE_WORKER_LAUNCH: (
            ChaosPoint.AFTER_PERMIT_PERSISTED_BEFORE_WORKER_LAUNCH
        ),
        DockerLifecycleFaultPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_IO: (
            ChaosPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_PROXY_IO
        ),
        DockerLifecycleFaultPoint.AFTER_FIRST_PROXY_FORWARD: (
            ChaosPoint.AFTER_FIRST_REQUEST_FORWARDED_BEFORE_RESPONSE_KNOWN
        ),
        DockerLifecycleFaultPoint.WORKER_CRASH_AFTER_TARGET_RESPONSE: (
            ChaosPoint.DURING_PHYSICAL_DETECTOR_RUN
        ),
        DockerLifecycleFaultPoint.AFTER_PROXY_RESULT_BEFORE_EVIDENCE_NORMALIZATION: (
            ChaosPoint.AFTER_RESPONSE_BEFORE_EVIDENCE_PERSIST
        ),
        DockerLifecycleFaultPoint.AFTER_EVIDENCE_NORMALIZATION_BEFORE_PERSISTENCE: (
            ChaosPoint.AFTER_EVIDENCE_BEFORE_PROOF
        ),
    }
    recovery = (
        recover_physical_detector_chaos(arguments.output, chaos_points[fault])
        if fault is not None
        else None
    )
    if recovery is not None and recovery.retry:
        retry_result = DetectorExecutionService(
            arguments.output / "safe-retry",
            key,
            (DockerDetectorAdapter(adapter_config, key),),
        ).execute(request.model_copy(update={"execution_attempt": 2}))
        fresh = bool(
            retry_result.authorization
            and retry_result.detector_run_id != recovery.detector_run_id
            and retry_result.authorization.payload.permit_id != recovery.permit_id
        )
        recovery = recovery.model_copy(
            update={"fresh_permit": fresh, "passed": recovery.passed and fresh}
        )
        (arguments.output / "recovery-result.json").write_text(
            recovery.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
    if recovery is not None:
        print(recovery.model_dump_json(indent=2))
    if fault is None:
        passed = result.status == "completed" and result.accounting.forwarded > 0
    elif fault in {
        DockerLifecycleFaultPoint.BEFORE_WORKER_LAUNCH,
        DockerLifecycleFaultPoint.AFTER_WORKER_LAUNCH_BEFORE_FIRST_IO,
    }:
        passed = result.accounting.forwarded == 0
    elif fault in {
        DockerLifecycleFaultPoint.AFTER_FIRST_PROXY_FORWARD,
        DockerLifecycleFaultPoint.WORKER_CRASH_AFTER_TARGET_RESPONSE,
    }:
        passed = result.status == "unknown_outcome" and result.accounting.unknown_outcomes == 1
    else:
        passed = result.accounting.forwarded == result.accounting.responses == 1
    return 0 if passed and (recovery is None or recovery.passed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
