from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from astp.detector_execution import DetectorExecutionRequest
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.docker_detector_adapter import DockerDetectorConfig, DockerDetectorRuntime
from astp.orchestrator_scheduler import rank_opportunity


def _run_suffix(request: DetectorExecutionRequest) -> str:
    key = json.dumps(
        [
            request.campaign_id,
            request.program_id,
            request.program_revision,
            request.detector.detector_id,
            request.target,
            request.execution_attempt,
        ],
        separators=(",", ":"),
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-network", required=True)
    arguments = parser.parse_args()
    arguments.output.mkdir(parents=True, exist_ok=True)
    registry = {item.detector_id: item for item in builtin_detector_registry()}
    digests = {
        "dalfox.reflected-bounded.v1": "sha256:4598aeb2403c27d5ecda7c9a853d88df255a2874e4cc772bfa33bcb88aa16afc",
        "playwright.dom-navigation-field.v1": "sha256:40aa366c13c49219029f280bb446990f9bcec3e88f768fee41deb61f73a44fb4",
        "sqlmap.detect-bounded.v1": "sha256:ca2886211f38fef3858d37e4f22a33c22051487d1872216efcccb53de15dbd16",
    }
    images = {
        "dalfox.reflected-bounded.v1": "astp/dalfox-worker:m52",
        "playwright.dom-navigation-field.v1": "astp/playwright-field-worker:m52",
        "sqlmap.detect-bounded.v1": "astp/sqlmap-worker:m52",
    }
    context = DetectorPolicyContext(
        disposition=MentionDisposition.EXPLICITLY_ALLOWED,
        target_in_scope=True,
        remaining_requests=100,
        browser_available=True,
    )

    def build(detector_id: str, target: str, parent: str | None = None):
        detector = registry[detector_id]
        opportunity = rank_opportunity(
            detector,
            program_id="local-program",
            target=target,
            signals=("reflected-parameter",),
            decision=decide_detector(detector, context),
            remaining_budget=100,
        )
        return DetectorExecutionRequest(
            campaign_id="physical-xss-chain",
            campaign_active=True,
            program_id="local-program",
            program_revision="rev-1",
            current_program_revision="rev-1",
            target=target,
            opportunity=opportunity,
            detector=detector,
            runtime_id=detector.required_runtime or detector.engine,
            runtime_digest=digests[detector_id],
            runtime_qualification_digest=digests[detector_id],
            lease_current=True,
            target_in_scope=True,
            semantic_review_complete=True,
            policy_context=context,
            global_remaining=100,
            program_remaining=100,
            detector_remaining=100,
            max_rps=1,
            proof_requirement=detector.proof_requirement,
            parent_candidate_id=parent,
        )

    target = "http://astp-m52-lab:8080/reflect?q=ASTP_XSS"
    dalfox = build("dalfox.reflected-bounded.v1", target)
    candidate = f"candidate-{_run_suffix(dalfox)}"
    playwright = build("playwright.dom-navigation-field.v1", target, candidate)
    sqlmap = build("sqlmap.detect-bounded.v1", "http://astp-m52-lab:8080/sql?id=1")
    config = DockerDetectorConfig(
        target_network=arguments.target_network,
        runtimes={
            detector_id: DockerDetectorRuntime(image=images[detector_id], image_digest=digest)
            for detector_id, digest in digests.items()
        },
        timeout_seconds=60,
    )
    (arguments.output / "docker-config.json").write_text(
        config.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    for index, request in enumerate((dalfox, playwright, sqlmap), 1):
        (arguments.output / f"request-{index}.json").write_text(
            request.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )


if __name__ == "__main__":
    main()
