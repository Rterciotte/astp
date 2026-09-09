from __future__ import annotations

import argparse
import json
from pathlib import Path

from astp.detector_execution import DetectorExecutionRequest
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.docker_detector_adapter import (
    DockerDetectorAdapter,
    DockerDetectorConfig,
    DockerDetectorRuntime,
)
from astp.orchestrator import run_orchestrator_execution
from astp.orchestrator_models import AutonomousCampaignConfig
from astp.orchestrator_scheduler import rank_opportunity


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-network", required=True)
    parser.add_argument("--runtime-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-cli-inputs", action="store_true")
    arguments = parser.parse_args()
    detector = next(
        item for item in builtin_detector_registry() if item.detector_id == "nuclei.astp-lab-cve.v1"
    )
    context = DetectorPolicyContext(
        disposition=MentionDisposition.EXPLICITLY_ALLOWED,
        target_in_scope=True,
        remaining_requests=10,
    )
    target = "http://astp-m52-lab:8080"
    opportunity = rank_opportunity(
        detector,
        program_id="local-program",
        target=target,
        signals=("cve-fixture",),
        decision=decide_detector(detector, context),
        remaining_budget=10,
    )
    key = "astp-local-signing-key-must-be-32-bytes-long"
    adapter_config = DockerDetectorConfig(
        target_network=arguments.target_network,
        proxy_image_digest="sha256:8bd3363e8dab429137feba77ab899048aca86dc77b22e816a3c61ea6393df15e",
        runtimes={
            detector.detector_id: DockerDetectorRuntime(
                image="astp/nuclei-worker:m52",
                image_digest=arguments.runtime_digest,
            )
        },
        timeout_seconds=30,
    )
    adapter = DockerDetectorAdapter(adapter_config, key)
    request = DetectorExecutionRequest(
        campaign_id="physical-service-1",
        campaign_active=True,
        program_id="local-program",
        program_revision="rev-1",
        current_program_revision="rev-1",
        target=target,
        opportunity=opportunity,
        detector=detector,
        runtime_id="nuclei",
        runtime_digest=arguments.runtime_digest,
        runtime_qualification_digest=arguments.runtime_digest,
        lease_current=True,
        target_in_scope=True,
        semantic_review_complete=True,
        policy_context=context,
        global_remaining=10,
        program_remaining=10,
        detector_remaining=10,
        max_rps=1.0,
        proof_requirement=detector.proof_requirement,
    )
    if arguments.prepare_cli_inputs:
        arguments.output.mkdir(parents=True, exist_ok=True)
        (arguments.output / "docker-config.json").write_text(
            adapter_config.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        (arguments.output / "detector-request.json").write_text(
            request.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps({"prepared": True, "output": str(arguments.output)}))
        return 0
    snapshot, results = run_orchestrator_execution(
        AutonomousCampaignConfig(
            campaign_id="physical-service-1",
            selected_program_ids=("local-program",),
            dry_run=False,
            execute=True,
        ),
        arguments.output,
        requests=(request,),
        adapters=(adapter,),
        signing_key=key,
    )
    result = results[0]
    print(result.model_dump_json(indent=2))
    print(snapshot)
    return 0 if result.status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
