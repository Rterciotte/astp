from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, Field

from astp.assessment_workflow import run_stored_assessment
from astp.browser_intake import BrowserCapture, load_capture
from astp.circuit_breaker import FailureCircuitBreaker
from astp.controlled_loop import run_controlled_queue
from astp.detector_execution import (
    DetectorExecutionRequest,
    DetectorExecutionService,
    DetectorRunStatus,
)
from astp.evidence_store import verify_evidence_manifest
from astp.execution_trace import append_trace_event
from astp.feedback import apply_evidence_feedback
from astp.io import dump_yaml, load_model
from astp.lifecycle import verify_audit_chain
from astp.models import (
    Engagement,
    OperationalStatus,
    ProgramOperationalAttestation,
    RiskClass,
    ScopeKind,
    SemanticExclusionRule,
    TestDefinition,
)
from astp.observation import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    ObservationError,
    observe_http,
)
from astp.permit_broker import broker_queue_item_permit
from astp.planner import (
    ObservationPlan,
    PlanItemStatus,
    TargetSemanticAssessment,
    build_observation_plan,
)
from astp.policy_snapshot import capture_policy_snapshot
from astp.program_catalog import BugBountyWorkspace, ProgramSyncStatus
from astp.program_intake import compile_program
from astp.program_models import BugBountyProgram
from astp.program_preflight import _capture_status
from astp.program_runtime import create_operational_attestation
from astp.session_ledger import initialize_session_ledger
from astp.target_discovery import CandidateKind, CandidateSafety, TargetCandidate
from astp.target_registry import RegistryEntry, TargetRegistry, empty_registry, save_registry
from astp.work_queue import build_fair_work_queue


class NightlyTargetSemanticReview(BaseModel):
    target: str
    semantic_exclusion_clears: set[str] = Field(default_factory=set)
    semantic_exclusion_matches: set[str] = Field(default_factory=set)
    reviewed_at: datetime | None = None
    note: str | None = None


class NightlySemanticReviewFile(BaseModel):
    schema_version: str = "1"
    program_id: str
    source_content_sha256: str
    guardrails: list[SemanticExclusionRule] = Field(default_factory=list)
    reviews: list[NightlyTargetSemanticReview] = Field(default_factory=list)


def _validated_semantic_assessments(
    review: NightlySemanticReviewFile | None,
    *,
    program: BugBountyProgram,
    engagement: Engagement,
) -> dict[str, TargetSemanticAssessment]:
    if review is None:
        return {}
    if review.program_id != program.id:
        raise ValueError(
            f"semantic review belongs to program {review.program_id!r}, expected {program.id!r}"
        )
    if review.source_content_sha256 != program.source.content_sha256:
        raise ValueError(
            "semantic review is stale: source_content_sha256 does not match the synchronized "
            "program revision"
        )

    known_ids = {rule.id for rule in engagement.constraints.semantic_exclusions}
    assessments: dict[str, TargetSemanticAssessment] = {}
    for row in review.reviews:
        target = row.target.strip()
        if not target:
            raise ValueError("semantic review target must not be empty")
        if target in assessments:
            raise ValueError(f"duplicate semantic review target: {target}")
        contradictory = row.semantic_exclusion_clears & row.semantic_exclusion_matches
        if contradictory:
            raise ValueError(
                "semantic review contains conflicting clear/match decisions for "
                f"{target}: " + ", ".join(sorted(contradictory))
            )
        unknown = (row.semantic_exclusion_clears | row.semantic_exclusion_matches) - known_ids
        if unknown:
            raise ValueError(
                f"semantic review for {target} contains unknown guardrail IDs: "
                + ", ".join(sorted(unknown))
            )
        if (
            row.semantic_exclusion_clears or row.semantic_exclusion_matches
        ) and row.reviewed_at is None:
            raise ValueError(
                f"semantic review for {target} has decisions but no reviewed_at timestamp"
            )
        assessments[target] = TargetSemanticAssessment(
            semantic_exclusion_clears=set(row.semantic_exclusion_clears),
            semantic_exclusion_matches=set(row.semantic_exclusion_matches),
        )
    return assessments


def _semantic_review_template(
    *,
    program: BugBountyProgram,
    engagement: Engagement,
    registry: TargetRegistry,
    existing: NightlySemanticReviewFile | None = None,
) -> NightlySemanticReviewFile:
    existing_by_target = {row.target: row for row in existing.reviews} if existing else {}
    reviews: list[NightlyTargetSemanticReview] = []
    for entry in registry.entries:
        prior = existing_by_target.get(entry.canonical_target)
        reviews.append(
            prior.model_copy(deep=True)
            if prior is not None
            else NightlyTargetSemanticReview(target=entry.canonical_target)
        )
    return NightlySemanticReviewFile(
        program_id=program.id,
        source_content_sha256=program.source.content_sha256,
        guardrails=list(engagement.constraints.semantic_exclusions),
        reviews=reviews,
    )


def _plan_semantic_block_reason(plan: ObservationPlan) -> str | None:
    blocked = [
        row
        for row in plan.items
        if row.status in {PlanItemStatus.BLOCKED_CONTEXT, PlanItemStatus.BLOCKED_POLICY}
        and "semantic deny guardrail" in row.reason.lower()
    ]
    if not blocked:
        return None
    return (
        f"{len(blocked)} target(s) blocked by semantic deny guardrail review; "
        "edit semantic-review-template.yaml and rerun with --semantic-review-file"
    )


class NightlyProgramResult(BaseModel):
    program_id: str
    program_name: str
    status: Literal[
        "completed",
        "planned",
        "blocked",
        "failed",
        "no_targets",
        "no_authorizable_actions",
    ]
    reason: str
    engagement_path: str | None = None
    registry_path: str | None = None
    report_path: str | None = None
    assessment_result_path: str | None = None
    observed_targets: list[str] = Field(default_factory=list)
    network_actions: int = 0
    permits_issued: int = 0
    evidence_records: int = 0
    normalized_signals: int = 0
    finding_candidates: int = 0
    correlated_findings: int = 0


class NightlyCampaignSummary(BaseModel):
    schema_version: str = "1"
    campaign_id: str
    platform: str
    started_at: datetime
    finished_at: datetime
    execute: bool
    program_results: list[NightlyProgramResult] = Field(default_factory=list)

    @property
    def completed(self) -> int:
        return sum(row.status == "completed" for row in self.program_results)

    @property
    def blocked(self) -> int:
        return sum(row.status == "blocked" for row in self.program_results)

    @property
    def failed(self) -> int:
        return sum(row.status == "failed" for row in self.program_results)

    @property
    def network_actions(self) -> int:
        return sum(row.network_actions for row in self.program_results)

    @property
    def permits_issued(self) -> int:
        return sum(row.permits_issued for row in self.program_results)


class NightlyDetectorOutcome(BaseModel):
    permit_id: str
    evidence_id: str | None = None
    candidate_id: str | None = None
    finding_id: str | None = None
    attempted: int = 0
    forwarded: int = 0
    responses: int = 0
    blocked_before_io: int = 0
    failed_after_io: int = 0
    unknown_outcomes: int = 0


class NightlyDetectorRequestBuilder(Protocol):
    def __call__(self, queue_item, engagement: Engagement) -> DetectorExecutionRequest: ...


class ServiceNightlyDetectorExecutor:
    """Nightly execution boundary backed only by DetectorExecutionService."""

    def __init__(
        self,
        service: DetectorExecutionService,
        request_builder: NightlyDetectorRequestBuilder,
    ) -> None:
        self.service = service
        self.request_builder = request_builder

    def execute(self, queue_item, engagement: Engagement) -> NightlyDetectorOutcome:
        result = self.service.execute(self.request_builder(queue_item, engagement))
        if result.status is DetectorRunStatus.BLOCKED_BEFORE_IO:
            raise ValueError(result.message_redacted or "detector blocked before I/O")
        if result.status is DetectorRunStatus.UNKNOWN_OUTCOME:
            raise ObservationError("detector outcome is unknown and cannot be replayed blindly")
        if result.status is DetectorRunStatus.FAILED:
            raise ObservationError(result.message_redacted or "detector execution failed")
        if result.authorization is None:
            raise ValueError("completed detector run lacks authorization")
        return NightlyDetectorOutcome(
            permit_id=result.authorization.payload.permit_id,
            evidence_id=(
                result.artifacts.evidence_ids[0] if result.artifacts.evidence_ids else None
            ),
            candidate_id=result.candidate_id,
            finding_id=result.finding_id,
            attempted=result.accounting.attempted,
            forwarded=result.accounting.forwarded,
            responses=result.accounting.responses,
            blocked_before_io=result.accounting.blocked_before_io,
            failed_after_io=result.accounting.failed_after_io,
            unknown_outcomes=result.accounting.unknown_outcomes,
        )


def _slug(value: str) -> str:
    result = "".join(ch.lower() if ch.isalnum() else "-" for ch in value)
    while "--" in result:
        result = result.replace("--", "-")
    return result.strip("-") or "program"


def _permit_keyring() -> tuple[str, dict[str, str]]:
    serialized = os.environ.get("ASTP_PERMIT_KEYS")
    active_key_id = os.environ.get("ASTP_PERMIT_ACTIVE_KEY_ID", "local-v1")
    if serialized:
        raw = json.loads(serialized)
        if not isinstance(raw, dict) or not all(
            isinstance(key_id, str) and isinstance(value, str) for key_id, value in raw.items()
        ):
            raise ValueError("ASTP_PERMIT_KEYS must map key IDs to string secrets.")
        keys = dict(raw)
    else:
        legacy = os.environ.get("ASTP_PERMIT_KEY")
        if not legacy:
            raise ValueError("ASTP_PERMIT_KEY or ASTP_PERMIT_KEYS is required for --execute.")
        keys = {active_key_id: legacy}
    if active_key_id not in keys:
        raise ValueError(f"Active permit key ID {active_key_id!r} is not present in the keyring.")
    if any(len(value.encode("utf-8")) < 32 for value in keys.values()):
        raise ValueError("Permit signing keys must contain at least 32 bytes.")
    return active_key_id, keys


def _seed_target_for_rule(kind: ScopeKind, value: str) -> str | None:
    value = value.strip()
    if kind == ScopeKind.URL_PREFIX:
        return value if value.startswith(("http://", "https://")) else None
    if kind in {ScopeKind.DOMAIN, ScopeKind.WILDCARD_DOMAIN}:
        host = value.removeprefix("*.").strip().strip("/")
        return f"https://{host}/" if host else None
    # Never turn a CIDR into guessed HTTP endpoints.
    return None


def build_scope_seed_registry(
    engagement: Engagement,
    *,
    now: datetime | None = None,
) -> TargetRegistry:
    """Seed only explicit HTTP-capable scope roots; every seed still needs policy + permit."""
    current = now or datetime.now(UTC)
    registry = empty_registry(engagement.id, now=current)
    seen: set[str] = set()
    for rule in engagement.scope.allowed:
        target = _seed_target_for_rule(rule.kind, rule.value)
        if not target or target in seen:
            continue
        seen.add(target)
        digest = hashlib.sha256(f"{engagement.id}|scope-seed|{target}".encode()).hexdigest()[:16]
        candidate = TargetCandidate(
            id=f"target-{digest}",
            canonical_target=target,
            display_target=target,
            kind=CandidateKind.LINK,
            safety=CandidateSafety.READY_FOR_POLICY,
            in_scope=True,
            same_origin=True,
            requires_new_permit=True,
            requires_semantic_assessment=bool(engagement.constraints.semantic_exclusions),
            executable=False,
            reason=(
                "Seeded from an explicit normalized program scope rule; "
                "policy evaluation and a fresh permit are still required."
            ),
            provenance=(),
            discovered_at=current,
        )
        registry.entries.append(
            RegistryEntry(
                canonical_target=target,
                candidate_ids=[candidate.id],
                provenance=[],
                latest_candidate=candidate,
                first_seen_at=current,
                last_seen_at=current,
            )
        )
    registry.entries.sort(key=lambda row: row.canonical_target)
    return registry


def _attestation_from_capture(
    *,
    program: BugBountyProgram,
    capture_path: Path | None,
    engagement: Engagement,
) -> ProgramOperationalAttestation:
    capture: BrowserCapture | None = None
    if capture_path is not None and capture_path.is_file():
        capture = load_capture(capture_path)

    requires_online = bool(engagement.program and engagement.program.requires_online)
    if capture is None:
        if requires_online:
            raise ValueError(
                "program requires fresh ONLINE status but no authenticated detail capture exists"
            )
        return create_operational_attestation(
            program,
            status=OperationalStatus.UNKNOWN,
            source_type="nightly_campaign",
            note="Operational status not required by this program policy.",
        )

    status, source_type, evidence = _capture_status(
        capture,
        platform=program.platform,
    )
    if requires_online and status == OperationalStatus.OFFLINE:
        raise ValueError(
            "program requires ONLINE status but authenticated browser evidence "
            "explicitly indicates OFFLINE"
        )
    if requires_online and status != OperationalStatus.ONLINE:
        raise ValueError(
            "program requires fresh ONLINE status but authenticated browser evidence "
            "does not prove the program is currently ONLINE"
        )

    return create_operational_attestation(
        program,
        status=status,
        source_type=source_type or "authenticated_browser",
        observed_at=capture.captured_at,
        note=(
            evidence
            or "Operational status derived conservatively from authenticated browser capture."
        ),
    )


def _observation_test() -> TestDefinition:
    return TestDefinition(
        id="nightly-http-observation",
        title="Bounded nightly HTTP observation",
        category="web",
        risk_class=RiskClass.SAFE_ACTIVE,
        required_context=[],
        evidence_required=["http_response"],
        description=(
            "Read-only GET observation used by ASTP nightly campaigns. "
            "Each request still requires a fresh exact execution permit."
        ),
    )


def _filter_unseen(plan: ObservationPlan, observed: set[str]) -> ObservationPlan:
    return plan.model_copy(
        update={"items": [row for row in plan.items if row.target not in observed]}
    )


def _write_campaign_markdown(summary: NightlyCampaignSummary, output: Path) -> None:
    lines = [
        f"# ASTP Nightly Campaign — {summary.campaign_id}",
        "",
        f"- Platform: `{summary.platform}`",
        f"- Execute: `{'YES' if summary.execute else 'NO'}`",
        f"- Programs: `{len(summary.program_results)}`",
        f"- Completed: `{summary.completed}`",
        f"- Blocked: `{summary.blocked}`",
        f"- Failed: `{summary.failed}`",
        f"- Network actions: `{summary.network_actions}`",
        f"- Permits issued: `{summary.permits_issued}`",
        "",
        "## Programs",
        "",
    ]
    for row in summary.program_results:
        lines.extend(
            [
                f"### {row.program_name}",
                "",
                f"- Status: `{row.status}`",
                f"- Reason: {row.reason}",
                f"- Network actions: `{row.network_actions}`",
                f"- Permits issued: `{row.permits_issued}`",
                f"- Evidence records: `{row.evidence_records}`",
                f"- Finding candidates: `{row.finding_candidates}`",
                f"- Correlated findings: `{row.correlated_findings}`",
            ]
        )
        if row.report_path:
            lines.append(f"- Report: `{row.report_path}`")
        lines.append("")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def run_nightly_campaign(
    *,
    catalog_path: Path,
    output_directory: Path,
    execute: bool = False,
    max_programs: int = 20,
    max_actions_per_program: int = 10,
    max_requests_per_program: int = 10,
    max_errors_per_program: int = 2,
    max_rounds: int = 2,
    max_link_candidates: int = 30,
    permit_ttl_seconds: int = 120,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    persist_body: bool = True,
    program_ids: list[str] | None = None,
    semantic_review_paths: list[Path] | None = None,
    detector_executor: ServiceNightlyDetectorExecutor | None = None,
) -> NightlyCampaignSummary:
    """Run a bounded multi-program campaign from already synchronized program rules."""
    if max_programs < 1:
        raise ValueError("max_programs must be at least 1")
    if max_actions_per_program < 1 or max_requests_per_program < 1:
        raise ValueError("per-program action/request budgets must be at least 1")
    if max_errors_per_program < 1:
        raise ValueError("max_errors_per_program must be at least 1")
    if max_rounds < 1:
        raise ValueError("max_rounds must be at least 1")
    if permit_ttl_seconds < 1 or permit_ttl_seconds > 900:
        raise ValueError("permit_ttl_seconds must be between 1 and 900")

    workspace = load_model(catalog_path, BugBountyWorkspace)
    semantic_reviews: dict[str, NightlySemanticReviewFile] = {}
    for review_path in semantic_review_paths or []:
        review = load_model(review_path, NightlySemanticReviewFile)
        if review.program_id in semantic_reviews:
            raise ValueError(
                f"multiple semantic review files supplied for program {review.program_id}"
            )
        semantic_reviews[review.program_id] = review

    started = datetime.now(UTC)
    campaign_id = started.strftime("nightly-%Y%m%dT%H%M%SZ")
    campaign_root = output_directory / campaign_id
    campaign_root.mkdir(parents=True, exist_ok=True)

    key_id: str | None = None
    keys: dict[str, str] | None = None
    if execute and detector_executor is None:
        key_id, keys = _permit_keyring()

    selected_items = workspace.programs
    if program_ids:
        requested_ids = list(dict.fromkeys(program_id.strip() for program_id in program_ids))
        if any(not program_id for program_id in requested_ids):
            raise ValueError("program_ids must not contain empty values")
        by_id = {item.candidate.id: item for item in workspace.programs}
        unknown_ids = [program_id for program_id in requested_ids if program_id not in by_id]
        if unknown_ids:
            raise ValueError("unknown program ID(s): " + ", ".join(unknown_ids))
        selected_items = [by_id[program_id] for program_id in requested_ids]

    test = _observation_test()
    program_results: list[NightlyProgramResult] = []
    for item in selected_items[:max_programs]:
        try:
            result = _run_program(
                item=item,
                test=test,
                campaign_root=campaign_root,
                execute=execute,
                key_id=key_id,
                keys=keys,
                max_actions=max_actions_per_program,
                max_requests=max_requests_per_program,
                max_errors=max_errors_per_program,
                max_rounds=max_rounds,
                max_link_candidates=max_link_candidates,
                permit_ttl_seconds=permit_ttl_seconds,
                timeout_seconds=timeout_seconds,
                max_body_bytes=max_body_bytes,
                persist_body=persist_body,
                semantic_review=semantic_reviews.get(item.candidate.id),
                detector_executor=detector_executor,
            )
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            result = NightlyProgramResult(
                program_id=item.candidate.id,
                program_name=item.candidate.name,
                status="failed",
                reason=f"program processing failed: {type(exc).__name__}: {exc}",
            )
        program_results.append(result)

    summary = NightlyCampaignSummary(
        campaign_id=campaign_id,
        platform=workspace.platform,
        started_at=started,
        finished_at=datetime.now(UTC),
        execute=execute,
        program_results=program_results,
    )
    dump_yaml(summary, campaign_root / "campaign.yaml")
    _write_campaign_markdown(summary, campaign_root / "campaign.md")
    return summary


def _run_program(
    *,
    item,
    test: TestDefinition,
    campaign_root: Path,
    execute: bool,
    key_id: str | None,
    keys: dict[str, str] | None,
    max_actions: int,
    max_requests: int,
    max_errors: int,
    max_rounds: int,
    max_link_candidates: int,
    permit_ttl_seconds: int,
    timeout_seconds: float,
    max_body_bytes: int,
    persist_body: bool,
    semantic_review: NightlySemanticReviewFile | None,
    detector_executor: ServiceNightlyDetectorExecutor | None = None,
) -> NightlyProgramResult:
    program_id = item.candidate.id
    program_name = item.candidate.name
    program_root = campaign_root / _slug(program_id)
    program_root.mkdir(parents=True, exist_ok=True)

    if item.sync_status == ProgramSyncStatus.FAILED:
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="blocked",
            reason=f"catalog sync failed: {item.error or 'unknown error'}",
        )
    if not item.normalized_path:
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="blocked",
            reason="program detail has not been synchronized from the authenticated browser",
        )

    try:
        program = load_model(Path(item.normalized_path), BugBountyProgram)
    except (OSError, ValueError, TypeError) as exc:
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="failed",
            reason=f"cannot load normalized program: {exc}",
        )

    if program.unresolved_issues:
        codes = ", ".join(sorted({row.code for row in program.unresolved_issues}))
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="blocked",
            reason=f"unresolved program-policy review issues: {codes}",
        )

    try:
        engagement = compile_program(program)
    except ValueError as exc:
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="blocked",
            reason=str(exc),
        )

    engagement_path = program_root / "engagement.yaml"
    test_path = program_root / "test.yaml"
    dump_yaml(engagement, engagement_path)
    dump_yaml(test, test_path)

    registry = build_scope_seed_registry(engagement)
    registry_path = program_root / "target-registry.yaml"
    save_registry(registry, registry_path)

    # Semantic review is an offline, target-specific policy artifact. Generate
    # its template before the runtime ONLINE gate so an expired/missing browser
    # attestation cannot prevent an operator from completing policy review.
    semantic_assessments = _validated_semantic_assessments(
        semantic_review,
        program=program,
        engagement=engagement,
    )
    semantic_template_path = program_root / "semantic-review-template.yaml"
    if engagement.constraints.semantic_exclusions:
        dump_yaml(
            _semantic_review_template(
                program=program,
                engagement=engagement,
                registry=registry,
                existing=semantic_review,
            ),
            semantic_template_path,
        )

    if not registry.entries:
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="no_targets",
            reason="no HTTP seed target could be derived safely from explicit scope",
            engagement_path=str(engagement_path),
            registry_path=str(registry_path),
        )

    # ONLINE status remains mandatory before planning/execution. Moving this
    # gate below template generation does not authorize or perform network I/O.
    try:
        attestation = _attestation_from_capture(
            program=program,
            capture_path=Path(item.capture_path) if item.capture_path else None,
            engagement=engagement,
        )
    except ValueError as exc:
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="blocked",
            reason=str(exc),
            engagement_path=str(engagement_path),
            registry_path=str(registry_path),
        )

    dump_yaml(attestation, program_root / "program-status-attestation.yaml")

    initial_plan = build_observation_plan(
        registry,
        engagement,
        test,
        semantic_target_assessments=(
            semantic_assessments if engagement.constraints.semantic_exclusions else None
        ),
        operational_attestation=attestation,
        requested_rps=engagement.constraints.max_requests_per_second,
    )
    initial_queue = build_fair_work_queue(
        [initial_plan],
        max_active_programs=1,
        max_items=max_actions,
    )
    dump_yaml(initial_plan, program_root / "plan-round-1.yaml")
    dump_yaml(initial_queue, program_root / "queue-round-1.yaml")

    if not initial_queue.items:
        semantic_reason = _plan_semantic_block_reason(initial_plan)
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="blocked" if semantic_reason else "no_authorizable_actions",
            reason=semantic_reason or "policy planning produced no authorizable GET observations",
            engagement_path=str(engagement_path),
            registry_path=str(registry_path),
        )

    if not execute:
        return NightlyProgramResult(
            program_id=program_id,
            program_name=program_name,
            status="planned",
            reason=(
                f"{len(initial_queue.items)} authorizable observations planned; "
                "network execution disabled because --execute was not supplied"
            ),
            engagement_path=str(engagement_path),
            registry_path=str(registry_path),
        )

    if detector_executor is None:
        assert key_id is not None and keys is not None
    evidence_dir = program_root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = program_root / "evidence-manifest.jsonl"
    audit_path = program_root / "audit.jsonl"
    state_path = program_root / "permit-state.json"
    runtime_db = program_root / "runtime.db"
    rate_state = program_root / "rate-state.json"
    ledger_db = program_root / "session-ledger.db"
    trace_path = program_root / "execution-trace.jsonl"

    observed_targets: set[str] = set()
    detector_evidence_ids: set[str] = set()
    detector_candidate_ids: set[str] = set()
    detector_finding_ids: set[str] = set()
    network_actions = 0
    permits_issued = 0
    stop_reason = "queue exhausted"

    for round_no in range(1, max_rounds + 1):
        remaining = min(max_actions - network_actions, max_requests - network_actions)
        if remaining <= 0:
            stop_reason = "campaign per-program budget exhausted"
            break

        plan = build_observation_plan(
            registry,
            engagement,
            test,
            semantic_target_assessments=(
                semantic_assessments if engagement.constraints.semantic_exclusions else None
            ),
            operational_attestation=attestation,
            requested_rps=engagement.constraints.max_requests_per_second,
        )
        plan = _filter_unseen(plan, observed_targets)
        queue = build_fair_work_queue(
            [plan],
            max_active_programs=1,
            max_items=remaining,
        )
        dump_yaml(plan, program_root / f"plan-round-{round_no}.yaml")
        dump_yaml(queue, program_root / f"queue-round-{round_no}.yaml")
        if not queue.items:
            break

        session_id = f"{_slug(program_id)}-r{round_no}"
        initialize_session_ledger(ledger_db, session_id)
        snapshot = capture_policy_snapshot(engagement, test)
        append_trace_event(trace_path, "session.started", message=session_id)

        def executor(queue_item, _session_id=session_id):
            nonlocal permits_issued, network_actions, registry
            if detector_executor is not None:
                outcome = detector_executor.execute(queue_item, engagement)
                permits_issued += 1
                network_actions += 1
                observed_targets.add(queue_item.target)
                if outcome.evidence_id:
                    detector_evidence_ids.add(outcome.evidence_id)
                if outcome.candidate_id:
                    detector_candidate_ids.add(outcome.candidate_id)
                if outcome.finding_id:
                    detector_finding_ids.add(outcome.finding_id)
                append_trace_event(
                    trace_path,
                    "detector.completed",
                    queue_id=queue_item.queue_id,
                    permit_id=outcome.permit_id,
                    evidence_id=outcome.evidence_id,
                    message=(
                        f"attempted={outcome.attempted};forwarded={outcome.forwarded};"
                        f"responses={outcome.responses};blocked={outcome.blocked_before_io};"
                        f"failed={outcome.failed_after_io};unknown={outcome.unknown_outcomes}"
                    ),
                )
                return (
                    outcome.permit_id,
                    outcome.evidence_id or f"no-evidence-{queue_item.queue_id}",
                )
            receipt = broker_queue_item_permit(
                queue_item,
                engagement,
                test,
                keys[key_id],
                key_id=key_id,
                ttl_seconds=permit_ttl_seconds,
                operational_attestation=attestation,
                requested_rps=engagement.constraints.max_requests_per_second,
            )
            permits_issued += 1
            append_trace_event(
                trace_path,
                "permit.issued",
                queue_id=queue_item.queue_id,
                permit_id=receipt.permit.payload.permit_id,
            )
            evidence_path = evidence_dir / f"{_session_id}-{queue_item.queue_id}.json"
            observation = observe_http(
                receipt.permit,
                engagement,
                test,
                keys,
                target=queue_item.target,
                method=queue_item.method,
                identity=None,
                requested_rps=engagement.constraints.max_requests_per_second,
                state_path=state_path,
                audit_path=audit_path,
                evidence_path=evidence_path,
                manifest_path=manifest_path,
                rate_state_path=rate_state,
                runtime_db_path=runtime_db,
                timeout_seconds=timeout_seconds,
                max_body_bytes=max_body_bytes,
                persist_body=persist_body,
            )
            network_actions += 1
            observed_targets.add(queue_item.target)
            append_trace_event(
                trace_path,
                "evidence.recorded",
                queue_id=queue_item.queue_id,
                permit_id=receipt.permit.payload.permit_id,
                evidence_id=observation.evidence.evidence_id,
            )
            feedback = apply_evidence_feedback(
                observation.evidence,
                engagement,
                registry,
                include_links=True,
                max_candidates=max_link_candidates,
            )
            registry = feedback.registry
            save_registry(registry, registry_path)
            if engagement.constraints.semantic_exclusions:
                dump_yaml(
                    _semantic_review_template(
                        program=program,
                        engagement=engagement,
                        registry=registry,
                        existing=semantic_review,
                    ),
                    semantic_template_path,
                )
            return receipt.permit.payload.permit_id, observation.evidence.evidence_id

        try:
            controlled = run_controlled_queue(
                queue,
                engagement,
                test,
                attestation,
                snapshot,
                ledger_db,
                session_id,
                executor,
                max_actions=min(remaining, len(queue.items)),
                max_requests=min(remaining, len(queue.items)),
                max_errors=max_errors,
                max_actions_per_origin=max_actions,
                breaker=FailureCircuitBreaker(max_consecutive_failures=max(1, max_errors)),
            )
        except ObservationError as exc:
            stop_reason = f"observation error: {exc}"
            append_trace_event(trace_path, "session.finished", message=stop_reason)
            break

        stop_reason = controlled.stop_reason or "queue exhausted"
        append_trace_event(trace_path, "session.finished", message=stop_reason)

    save_registry(registry, registry_path)

    if manifest_path.exists():
        valid, message = verify_evidence_manifest(manifest_path, verify_artifacts=True)
        if not valid:
            return NightlyProgramResult(
                program_id=program_id,
                program_name=program_name,
                status="failed",
                reason=f"evidence manifest verification failed: {message}",
                engagement_path=str(engagement_path),
                registry_path=str(registry_path),
                observed_targets=sorted(observed_targets),
                network_actions=network_actions,
                permits_issued=permits_issued,
            )

    if audit_path.exists():
        valid, message = verify_audit_chain(audit_path)
        if not valid:
            return NightlyProgramResult(
                program_id=program_id,
                program_name=program_name,
                status="failed",
                reason=f"audit-chain verification failed: {message}",
                engagement_path=str(engagement_path),
                registry_path=str(registry_path),
                observed_targets=sorted(observed_targets),
                network_actions=network_actions,
                permits_issued=permits_issued,
            )

    assessment_dir = program_root / "assessment"
    assessment = run_stored_assessment(
        session_id=f"{_slug(program_id)}-nightly",
        evidence_directory=evidence_dir,
        registry=registry,
        engagement=engagement,
        test=test,
        output_directory=assessment_dir,
        operational_attestation=attestation,
        # Stored assessment may discover new targets. Keep its legacy global semantic
        # clearance empty so offline replanning cannot authorize an unreviewed target.
        semantic_exclusion_clears=set(),
        requested_rps=engagement.constraints.max_requests_per_second,
        excluded_finding_terms=set(
            engagement.program.excluded_finding_types if engagement.program is not None else []
        ),
    )

    return NightlyProgramResult(
        program_id=program_id,
        program_name=program_name,
        status="completed",
        reason=stop_reason,
        engagement_path=str(engagement_path),
        registry_path=str(registry_path),
        report_path=str(assessment.report_path),
        assessment_result_path=str(assessment.assessment_result_path),
        observed_targets=sorted(observed_targets),
        network_actions=network_actions,
        permits_issued=permits_issued,
        evidence_records=assessment.evidence_records + len(detector_evidence_ids),
        normalized_signals=assessment.normalized_signals,
        finding_candidates=assessment.finding_candidates + len(detector_candidate_ids),
        correlated_findings=assessment.correlated_findings + len(detector_finding_ids),
    )
