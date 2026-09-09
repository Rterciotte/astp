from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from astp.browser_intake import BrowserCapture, BrowserOperationalSignal, write_capture
from astp.detector_execution import DetectorExecutionRequest, DetectorExecutionService
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.docker_detector_adapter import (
    DockerDetectorAdapter,
    DockerDetectorConfig,
    DockerDetectorRuntime,
)
from astp.io import dump_yaml
from astp.models import ScopeKind, ScopeRule
from astp.nightly_campaign import ServiceNightlyDetectorExecutor, run_nightly_campaign
from astp.orchestrator_scheduler import rank_opportunity
from astp.program_catalog import (
    BugBountyWorkspace,
    CatalogProgram,
    ProgramCandidate,
    ProgramSyncStatus,
)
from astp.program_models import (
    BugBountyProgram,
    ProgramOperationalStatus,
    ProgramScopeEntry,
    ProgramSourceSnapshot,
    ProgramVisibility,
    RuleEffect,
    RuleProvenance,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--target-network", required=True)
    arguments = parser.parse_args()
    arguments.root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)
    target = "http://astp-m52-lab:8080/"
    revision = "a" * 64
    program_path = arguments.root / "program.yaml"
    capture_path = arguments.root / "capture.json"
    catalog_path = arguments.root / "catalog.yaml"
    program = BugBountyProgram(
        id="local-program",
        name="Local M52",
        platform="local-bughunt-fixture",
        visibility=ProgramVisibility.PRIVATE,
        operational_status=ProgramOperationalStatus.ONLINE,
        scope=[
            ProgramScopeEntry(
                effect=RuleEffect.ALLOW,
                selector=ScopeRule(kind=ScopeKind.URL_PREFIX, value=target),
                provenance=RuleProvenance(
                    source_type="local_fixture", source_text=target, captured_at=now
                ),
            )
        ],
        reviewed_max_requests_per_second=1,
        source=ProgramSourceSnapshot(
            source_type="authenticated_browser",
            source_url="http://local-bughunt-fixture/program/local-program",
            captured_at=now,
            content_sha256=revision,
        ),
    )
    dump_yaml(program, program_path)
    write_capture(
        BrowserCapture(
            url="http://local-bughunt-fixture/program/local-program",
            text="Local M52 Publicado Submeter Relatório",
            operational_signals=[
                BrowserOperationalSignal(
                    kind="submission_control",
                    evidence="Submeter Relatório",
                    visible=True,
                    enabled=True,
                ),
                BrowserOperationalSignal(
                    kind="published_marker", evidence="Publicado", visible=True
                ),
            ],
            captured_at=now,
        ),
        capture_path,
    )
    dump_yaml(
        BugBountyWorkspace(
            platform="local-bughunt-fixture",
            source_url="http://local-bughunt-fixture/programs",
            programs=[
                CatalogProgram(
                    candidate=ProgramCandidate(
                        id="local-program",
                        name="Local M52",
                        detail_url="http://local-bughunt-fixture/program/local-program",
                        platform="local-bughunt-fixture",
                    ),
                    sync_status=ProgramSyncStatus.READY,
                    normalized_path=str(program_path),
                    capture_path=str(capture_path),
                    active=True,
                )
            ],
        ),
        catalog_path,
    )
    detector = next(
        item for item in builtin_detector_registry() if item.detector_id == "nuclei.astp-lab-cve.v1"
    )
    digest = "sha256:8074909a9b3bf948c9b75103df1367690b8bb0a039e4658e6616aea4205d3459"
    key = "astp-local-signing-key-must-be-32-bytes-long"
    service = DetectorExecutionService(
        arguments.root / "detector-service",
        key,
        (
            DockerDetectorAdapter(
                DockerDetectorConfig(
                    target_network=arguments.target_network,
                    proxy_image_digest="sha256:8bd3363e8dab429137feba77ab899048aca86dc77b22e816a3c61ea6393df15e",
                    runtimes={
                        detector.detector_id: DockerDetectorRuntime(
                            image="astp/nuclei-worker:m52", image_digest=digest
                        )
                    },
                    timeout_seconds=30,
                ),
                key,
            ),
        ),
    )

    def build(queue_item, _engagement):
        context = DetectorPolicyContext(
            disposition=MentionDisposition.EXPLICITLY_ALLOWED,
            target_in_scope=True,
            remaining_requests=10,
        )
        opportunity = rank_opportunity(
            detector,
            program_id="local-program",
            target=queue_item.target,
            signals=("known_cve",),
            decision=decide_detector(detector, context),
            remaining_budget=10,
        )
        return DetectorExecutionRequest(
            campaign_id="nightly-physical-local",
            campaign_active=True,
            program_id="local-program",
            program_revision=revision,
            current_program_revision=revision,
            target=queue_item.target,
            opportunity=opportunity,
            detector=detector,
            runtime_id="nuclei",
            runtime_digest=digest,
            runtime_qualification_digest=digest,
            lease_current=True,
            target_in_scope=True,
            semantic_review_complete=True,
            policy_context=context,
            global_remaining=10,
            program_remaining=10,
            detector_remaining=10,
            max_rps=1,
            proof_requirement=detector.proof_requirement,
        )

    summary = run_nightly_campaign(
        catalog_path=catalog_path,
        output_directory=arguments.root / "campaigns",
        execute=True,
        max_programs=1,
        max_actions_per_program=1,
        max_requests_per_program=1,
        detector_executor=ServiceNightlyDetectorExecutor(service, build),
    )
    print(summary.model_dump_json(indent=2))
    return 0 if summary.completed == 1 and summary.network_actions == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
