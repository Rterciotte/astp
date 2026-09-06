from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from astp.io import dump_yaml
from astp.models import (
    Constraints,
    Decision,
    Engagement,
    MethodPolicy,
    ProgramBinding,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.program_field_assessment import prepare_bounded_field_assessment
from astp.program_preflight import (
    PolicyDriftStatus,
    PreflightStatus,
    ProgramPreflightReport,
    _report_hash,
)


def _fixture(tmp_path: Path, *, eligible: bool = True, age_seconds: int = 0):
    now = datetime.now(UTC)
    engagement = Engagement(
        id="smartfit-field",
        name="Smart Fit field",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="smartfit.com")]),
        methods=MethodPolicy(
            passive=Decision.ALLOW,
            safe_active=Decision.ALLOW,
            state_changing=Decision.APPROVAL_REQUIRED,
            intrusive=Decision.DENY,
        ),
        constraints=Constraints(max_requests_per_second=1.0),
        program=ProgramBinding(
            program_id="p",
            platform="bughunt",
            source_content_sha256="a" * 64,
            requires_online=True,
        ),
    )
    engagement_path = tmp_path / "engagement.yaml"
    attestation_path = tmp_path / "attestation.yaml"
    engagement_path.write_text(dump_yaml(engagement), encoding="utf-8")
    attestation_path.write_text("placeholder: true\n", encoding="utf-8")
    payload = {
        "schema_version": "1",
        "program_id": "p",
        "program_name": "P",
        "platform": "bughunt",
        "status": (
            PreflightStatus.EXECUTION_ELIGIBLE.value if eligible else PreflightStatus.BLOCKED.value
        ),
        "execution_eligible": eligible,
        "evaluated_at": (now - timedelta(seconds=age_seconds)).isoformat(),
        "source_capture_fresh": True,
        "capture_age_seconds": 1.0,
        "policy_status": "ready",
        "policy_drift": PolicyDriftStatus.NONE.value,
        "current_policy_fingerprint": "b" * 64,
        "current_source_sha256": "a" * 64,
        "operational_status": "online",
        "full_pentest_ready": True,
        "engagement_path": str(engagement_path),
        "attestation_path": str(attestation_path),
        "reviewed_max_requests_per_second": 1.0,
        "blocking_reasons": (),
    }
    payload["report_hash"] = _report_hash(payload)
    report = ProgramPreflightReport.model_validate(payload)
    path = tmp_path / f"preflight-{report.report_hash}.json"
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return now, path


def test_prepare_exact_one_action(tmp_path):
    now, path = _fixture(tmp_path)
    prep, prep_path = prepare_bounded_field_assessment(
        tmp_path, preflight_path=path, target="https://smartfit.com/", now=now
    )
    assert prep.max_actions == 1
    assert prep.max_requests == 1
    assert prep.state_changing_allowed is False
    assert prep.broad_scanning_allowed is False
    assert prep_path.exists()


def test_prepare_rejects_out_of_scope_target(tmp_path):
    now, path = _fixture(tmp_path)
    with pytest.raises(ValueError, match="outside compiled engagement scope"):
        prepare_bounded_field_assessment(
            tmp_path, preflight_path=path, target="https://example.com/", now=now
        )


def test_prepare_rejects_stale_preflight(tmp_path):
    now, path = _fixture(tmp_path, age_seconds=301)
    with pytest.raises(ValueError, match="preflight report is stale"):
        prepare_bounded_field_assessment(
            tmp_path, preflight_path=path, target="https://smartfit.com/", now=now
        )


def test_prepare_rejects_rate_above_reviewed(tmp_path):
    now, path = _fixture(tmp_path)
    with pytest.raises(ValueError, match="exceeds reviewed/compiled"):
        prepare_bounded_field_assessment(
            tmp_path,
            preflight_path=path,
            target="https://smartfit.com/",
            requested_rps=2.0,
            now=now,
        )
