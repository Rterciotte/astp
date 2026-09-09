from datetime import UTC, datetime

import pytest
from typer.testing import CliRunner

from astp.cli import app
from astp.detector_policy import DetectorPolicyContext, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.orchestrator import finalize_orchestrator, resume_orchestrator, start_orchestrator
from astp.orchestrator_manifest import CampaignManifest, verify_campaign_manifest
from astp.orchestrator_models import (
    ActionState,
    AutonomousCampaignConfig,
    CampaignReadiness,
    CampaignState,
    evaluate_readiness,
)
from astp.orchestrator_scheduler import (
    canonical_idempotency_key,
    effective_rate,
    rank_opportunity,
    schedule_retry,
    weighted_round_robin,
)
from astp.orchestrator_store import OrchestratorStore
from astp.platform_adapters import classify_bughunt_page


def config(campaign_id="nightly-test"):
    return AutonomousCampaignConfig(
        campaign_id=campaign_id, selected_program_ids=("a", "b"), dry_run=True, execute=False
    )


def test_one_command_dry_run_creates_durable_final_campaign(tmp_path):
    snapshot = start_orchestrator(config(), tmp_path)
    assert snapshot["campaign"]["state"] == CampaignState.COMPLETED.value
    assert (tmp_path / "campaign.db").is_file() and (tmp_path / "live-status.json").is_file()


def test_action_state_machine_and_global_idempotency(tmp_path):
    store = OrchestratorStore(tmp_path / "campaign.db")
    store.create_campaign(config())
    key = canonical_idempotency_key(
        program="a",
        target="https://example.test",
        method="GET",
        detector="http",
        policy_revision="1",
    )
    assert store.create_action("action-1", "nightly-test", "a", key)
    assert not store.create_action("action-2", "nightly-test", "a", key)
    store.transition_action("action-1", ActionState.UNPLANNED)
    with pytest.raises(ValueError, match="invalid state transition"):
        store.transition_action("action-1", ActionState.EXECUTING)


def test_unknown_outcome_is_not_blindly_resumed(tmp_path):
    root = tmp_path / "run"
    store = OrchestratorStore(root / "campaign.db")
    store.create_campaign(config())
    store.transition_campaign("nightly-test", CampaignState.PREFLIGHT, "ok")
    store.transition_campaign("nightly-test", CampaignState.READY, "ok")
    store.transition_campaign("nightly-test", CampaignState.RUNNING, "ok")
    store.create_action("action-1", "nightly-test", "a", "key")
    for state in (
        ActionState.UNPLANNED,
        ActionState.PLANNED,
        ActionState.AUTHORIZED,
        ActionState.PERMIT_ISSUED,
    ):
        store.transition_action("action-1", state)
    store.transition_action("action-1", ActionState.UNKNOWN_OUTCOME)
    store.transition_campaign("nightly-test", CampaignState.PAUSING, "stop")
    store.transition_campaign("nightly-test", CampaignState.PAUSED, "stop")
    with pytest.raises(ValueError, match="never replayed"):
        resume_orchestrator(store, "nightly-test", root)


def test_scheduler_is_fair_and_policy_blocked_work_never_enters():
    cap = next(
        item for item in builtin_detector_registry() if item.detector_id == "astp.http-posture.v1"
    )
    allowed = decide_detector(
        cap, DetectorPolicyContext(target_in_scope=True, remaining_requests=100)
    )
    rows = [
        rank_opportunity(
            cap,
            program_id=program,
            target=f"https://{program}.test",
            signals=("http",),
            decision=allowed,
            remaining_budget=100,
        )
        for program in ("a", "a", "b", "b")
    ]
    assert [item.program_id for item in weighted_round_robin(rows, limit=4)] == ["a", "b", "a", "b"]


def test_retry_and_adaptive_rate_are_bounded():
    now = datetime.now(UTC)
    assert schedule_retry("policy_denial", 1, now=now).retry is False
    assert schedule_retry("rate_limited", 1, now=now, retry_after_seconds=42).next_retry_at > now
    assert effective_rate(2, 1, 0.5) == 0.5


def test_bughunt_spa_semantic_readiness_rejects_listing():
    assert not classify_bughunt_page(
        "/programs/abc", "Programas disponíveis", {"program-card"}
    ).ready
    text = "scope regras recompensas " * 10
    assert classify_bughunt_page("/programs/abc", text, {"program-detail"}).ready


def test_final_report_and_manifest_are_verifiable(tmp_path):
    root = tmp_path / "run"
    start_orchestrator(
        AutonomousCampaignConfig(
            campaign_id="c", selected_program_ids=("a",), dry_run=False, execute=True
        ),
        root,
    )
    store = OrchestratorStore(root / "campaign.db")
    report = finalize_orchestrator(store, "c", root)
    manifest = CampaignManifest.model_validate_json((root / "campaign-manifest.json").read_text())
    assert report.is_file() and verify_campaign_manifest(manifest, root)


def test_campaign_manifest_rejects_path_escape(tmp_path):
    outside = tmp_path.parent / "outside-manifest-artifact.txt"
    outside.write_text("outside", encoding="utf-8")
    manifest = CampaignManifest(
        campaign_id="c", report_state="final", artifacts={"../outside-manifest-artifact.txt": "x"}
    )
    assert not verify_campaign_manifest(manifest, tmp_path)


def test_detector_run_accounting_reconciliation_is_exact(tmp_path):
    store = OrchestratorStore(tmp_path / "campaign.db")
    store.create_campaign(config())
    accounting = {
        "requests_attempted": 5,
        "requests_forwarded": 4,
        "responses_received": 4,
        "requests_blocked_before_io": 1,
        "requests_failed_after_io": 0,
    }
    store.reconcile_detector_run("nightly-test", accounting, authorized_budget=4)
    counters = store.snapshot("nightly-test")["counters"]
    assert counters["requests_attempted"] == 5
    assert counters["requests_forwarded"] == 4
    assert counters["requests_blocked_before_io"] == 1
    with pytest.raises(ValueError, match="invariant"):
        store.reconcile_detector_run(
            "nightly-test", {**accounting, "responses_received": 3}, authorized_budget=4
        )


def test_orchestrator_execute_cli_is_enabled_but_requires_typed_inputs(tmp_path):
    result = CliRunner().invoke(
        app,
        [
            "orchestrator-start",
            "--campaign-id",
            "physical-cli",
            "--all-ready",
            "--execute",
            "--root",
            str(tmp_path),
        ],
    )

    assert result.exit_code != 0
    assert "requires --docker-config" in result.output
    assert "remains disabled" not in result.output


def test_optional_runtime_gap_degrades_coverage_without_blocking_orchestration():
    assert (
        evaluate_readiness(
            required_prerequisites_blocked=False,
            optional_capabilities_unavailable=True,
        )
        is CampaignReadiness.DEGRADED_COVERAGE
    )
    assert (
        evaluate_readiness(
            required_prerequisites_blocked=True,
            optional_capabilities_unavailable=False,
        )
        is CampaignReadiness.BLOCKED
    )
