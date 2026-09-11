from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from astp.detector_execution import DetectorExecutionRequest, DetectorExecutionService
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.field_http_observation import (
    FieldHttpObservationAdapter,
    FieldHttpObservationConfig,
)
from astp.models import Engagement, ScopePolicy
from astp.orchestrator_scheduler import rank_opportunity


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--target-network", required=True)
    parser.add_argument("--proxy-digest", required=True)
    arguments = parser.parse_args()
    target_origin = "http://astp-field-lab:8080"
    detector = next(
        item
        for item in builtin_detector_registry()
        if item.detector_id == "astp.http-observation-field.v1"
    )
    context = DetectorPolicyContext(
        disposition=MentionDisposition.EXPLICITLY_ALLOWED,
        target_in_scope=True,
        remaining_requests=30,
    )

    def request(campaign: str, path: str, **changes) -> DetectorExecutionRequest:
        target = target_origin + path
        opportunity = rank_opportunity(
            detector,
            program_id="local-field-program",
            target=target,
            signals=("authorized-passive-observation",),
            decision=decide_detector(detector, context),
            remaining_budget=30,
        )
        values = {
            "campaign_id": campaign,
            "campaign_active": True,
            "program_id": "local-field-program",
            "program_revision": "local-field-revision",
            "current_program_revision": "local-field-revision",
            "target": target,
            "opportunity": opportunity,
            "detector": detector,
            "runtime_id": "counting-proxy",
            "runtime_digest": arguments.proxy_digest,
            "runtime_qualification_digest": arguments.proxy_digest,
            "engagement": Engagement(
                id="local-field-engagement", name="Local", scope=ScopePolicy()
            ),
            "target_in_scope": True,
            "semantic_review_complete": True,
            "policy_context": context,
            "global_remaining": 30,
            "program_remaining": 30,
            "detector_remaining": 30,
            "max_rps": 20,
            "proof_requirement": detector.proof_requirement,
            "user_agent": "Bughunt - Security Research",
            "authorized_path_prefix": "/",
        }
        values.update(changes)
        return DetectorExecutionRequest(**values)

    adapter = FieldHttpObservationAdapter(
        FieldHttpObservationConfig(
            target_network=arguments.target_network,
            proxy_image_digest=arguments.proxy_digest,
        ),
        "local-field-acceptance-signing-key",
    )
    results = []
    for item in (
        request("field-get", "/"),
        request("field-head", "/", http_method="HEAD"),
        request(
            "field-redirect-out",
            "/redirect-out",
            follow_redirects=True,
            max_redirects=1,
        ),
        request(
            "field-budget",
            "/redirect-in",
            follow_redirects=True,
            max_redirects=1,
            global_remaining=1,
            program_remaining=1,
            detector_remaining=1,
        ),
    ):
        service = DetectorExecutionService(
            arguments.root / item.campaign_id,
            "local-field-acceptance-signing-key",
            (adapter,),
        )
        results.append(service.execute(item))

    post_blocked = False
    try:
        request("field-post", "/", http_method="POST")
    except ValidationError:
        post_blocked = True

    report = {
        "results": [item.model_dump(mode="json") for item in results],
        "post_blocked_before_io": post_blocked,
        "real_target_requests": 0,
    }
    arguments.root.mkdir(parents=True, exist_ok=True)
    (arguments.root / "acceptance-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    get, head, external, budget = results
    passed = (
        get.status == "completed"
        and get.accounting.forwarded == get.accounting.responses == 1
        and head.status == "completed"
        and head.accounting.forwarded == head.accounting.responses == 1
        and external.status == "completed"
        and external.accounting.forwarded == external.accounting.responses == 1
        and external.artifacts.worker_receipt["redirects"][0]["followed"] is False
        and budget.status == "completed"
        and budget.accounting.forwarded == budget.accounting.responses == 1
        and budget.accounting.blocked_before_io == 1
        and post_blocked
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
