from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from astp.detector_execution import DetectorExecutionRequest, DetectorExecutionService
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.internal_detector_adapter import InternalDetectorAdapter
from astp.models import Engagement, ScopePolicy
from astp.orchestrator_scheduler import rank_opportunity
from astp.proof_model import ProofStateV2


def _request(detector_id, artifact, *, execution_attempt=1, **context_changes):
    detector = next(item for item in builtin_detector_registry() if item.detector_id == detector_id)
    values = {
        "disposition": MentionDisposition.EXPLICITLY_ALLOWED,
        "target_in_scope": True,
        "remaining_requests": 20,
        "available_identities": 2,
        "oast_available": True,
    }
    values.update(context_changes)
    context = DetectorPolicyContext(**values)
    target = "http://local.test/evidence"
    opportunity = rank_opportunity(
        detector,
        program_id="local",
        target=target,
        signals=("local-evidence",),
        decision=decide_detector(detector, context),
        remaining_budget=20,
    )
    return DetectorExecutionRequest(
        campaign_id="internal-campaign",
        campaign_active=True,
        program_id="local",
        program_revision="rev-1",
        current_program_revision="rev-1",
        target=target,
        opportunity=opportunity,
        detector=detector,
        runtime_id="astp-native",
        runtime_digest="sha256:astp-native-v1",
        runtime_qualification_digest="sha256:astp-native-v1",
        engagement=Engagement(id="engagement-local", name="Local", scope=ScopePolicy()),
        target_in_scope=True,
        semantic_review_complete=True,
        policy_context=context,
        identity_refs=("identity-a", "identity-b"),
        global_remaining=20,
        program_remaining=20,
        detector_remaining=20,
        max_rps=1,
        proof_requirement=detector.proof_requirement,
        input_artifact_path=str(artifact),
        execution_attempt=execution_attempt,
    )


def test_secret_service_persists_only_redacted_values_and_hashes(tmp_path) -> None:
    raw = "AKIAABCDEFGHIJKLMNOP eyJabcdefghijk.abcdefghijk.abcdefghijk postgres://user:pass@db/app api_key=abcdefghijklmnop"
    artifact = tmp_path / "secret-input.json"
    artifact.write_text(json.dumps({"content": raw}), encoding="utf-8")
    service = DetectorExecutionService(
        tmp_path / "run", "test-signing-key", (InternalDetectorAdapter(),)
    )

    result = service.execute(_request("astp.secret-exposure.v1", artifact))
    persisted = Path(result.artifacts.raw_output_path).read_text(encoding="utf-8")

    assert result.proof_after is ProofStateV2.REPRODUCED
    assert result.finding_id
    assert result.accounting.forwarded == 0
    assert "AKIAABCDEFGHIJKLMNOP" not in persisted
    assert "postgres://user:pass" not in persisted
    assert "value_sha256" in persisted


def test_idor_positive_and_negative_run_through_service(tmp_path) -> None:
    service = DetectorExecutionService(
        tmp_path / "runs", "test-signing-key", (InternalDetectorAdapter(),)
    )
    positive = tmp_path / "positive.json"
    positive.write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "identity_ref": "identity-a",
                        "status_code": 200,
                        "body": '{"email":"owner@test"}',
                        "expected_owner": True,
                    },
                    {
                        "identity_ref": "identity-b",
                        "status_code": 200,
                        "body": '{"email":"owner@test"}',
                        "expected_owner": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    negative = tmp_path / "negative.json"
    negative.write_text(
        json.dumps(
            {
                "observations": [
                    {
                        "identity_ref": "identity-a",
                        "status_code": 200,
                        "body": '{"email":"owner@test"}',
                        "expected_owner": True,
                    },
                    {
                        "identity_ref": "identity-b",
                        "status_code": 403,
                        "body": "forbidden",
                        "expected_owner": False,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    found = service.execute(_request("astp.idor-differential.v1", positive, execution_attempt=1))
    safe = service.execute(_request("astp.idor-differential.v1", negative, execution_attempt=2))

    assert found.proof_after is ProofStateV2.CONFIRMED and found.finding_id
    assert safe.finding_id is None


def test_oast_exact_callback_promotes_only_matching_payload(tmp_path) -> None:
    artifact = tmp_path / "oast.json"
    request = _request("astp.ssrf-oast.v1", artifact)
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
    digest = hashlib.sha256(key.encode()).hexdigest()
    now = datetime.now(UTC)
    permit_id = f"permit-{digest[:20]}"
    artifact.write_text(
        json.dumps(
            {
                "payload": {
                    "payload_id": "oast-exact",
                    "program_id": "local",
                    "target": request.target,
                    "action_id": f"action-{digest[16:32]}",
                    "permit_id": permit_id,
                    "detector_id": request.detector.detector_id,
                    "issued_at": now.isoformat(),
                },
                "callback": {
                    "payload_id": "oast-exact",
                    "protocol": "http",
                    "received_at": (now + timedelta(seconds=1)).isoformat(),
                    "source_hash": "local-source-hash",
                },
            }
        ),
        encoding="utf-8",
    )
    service = DetectorExecutionService(
        tmp_path / "run", "test-signing-key", (InternalDetectorAdapter(),)
    )

    result = service.execute(request)

    assert result.proof_after is ProofStateV2.CONFIRMED
    assert result.finding_id
    assert result.accounting.attempted == 0
