import json
import os
import secrets
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from astp.adapter_registry import builtin_adapter_registry, ensure_adapter_compatible
from astp.approval_workflow import ApprovalDecision, record_high_risk_approval
from astp.artifact_planner import plan_javascript_artifacts
from astp.assessment import assess_evidence, load_evidence_directory
from astp.assessment_completion import evaluate_pentest_completion
from astp.assessment_coverage import current_assessment_coverage
from astp.assessment_cycle import plan_safe_surface_observations
from astp.assessment_execution import (
    build_assessment_execution_plan,
    write_assessment_execution_plan,
)
from astp.assessment_manifest import (
    AssessmentManifest,
    build_assessment_manifest,
    verify_assessment_manifest,
)
from astp.assessment_resume import evaluate_assessment_resume
from astp.auth_session import AuthSessionProfile
from astp.authenticated_observation import observe_authenticated_http
from astp.authorization import AuthorizationRequest, authorize_test
from astp.authorization_differential import build_authorization_differential_plan
from astp.autonomy_session import prepare_autonomy_session
from astp.browser_intake import capture_to_text, load_capture
from astp.browser_runtime import browser_runtime_status
from astp.browser_worker_contract import BrowserWorkerContract
from astp.capability_action import CapabilityAction, CapabilityOperation
from astp.capability_dispatcher import dispatch_capability_observation
from astp.capability_evidence import derive_network_capability_evidence
from astp.capability_grant import SignedCapabilityGrant, issue_capability_grant
from astp.circuit_breaker import FailureCircuitBreaker
from astp.closure_gate import evaluate_closure
from astp.confidence import fuse_normalized_signals
from astp.controlled_loop import run_controlled_queue
from astp.differential_analysis import compare_authorization_evidence
from astp.end_to_end_plan import build_end_to_end_assessment_plan
from astp.evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from astp.evidence_quarantine import quarantine_evidence
from astp.evidence_store import SensitivityLabel, verify_evidence_manifest
from astp.execution_intent import build_execution_intent
from astp.execution_trace import append_trace_event, verify_execution_trace
from astp.external_adapter_contracts import builtin_external_adapter_contracts
from astp.external_adapter_runtime import adapter_runtime_available
from astp.feedback import apply_evidence_feedback
from astp.field_validation import validate_assessment_recovery
from astp.finding_repository import set_retest_state, upsert_finding
from astp.findings import FindingCandidate, FindingSet, correlate_findings
from astp.frontier import build_frontier
from astp.http_fingerprint import fingerprint_http
from astp.hypothesis import build_observation_hypotheses
from astp.io import dump_yaml, load_model, load_yaml
from astp.javascript_inventory import inventory_javascript
from astp.js_static_analysis import analyze_javascript_file
from astp.lifecycle import (
    append_audit_event,
    consume_execution_permit,
    permit_status,
    revoke_permit,
    verify_audit_chain,
)
from astp.lineage import build_assessment_lineage
from astp.method_strategy import choose_observation_method
from astp.models import (
    ApprovalArtifact,
    Decision,
    Engagement,
    EvaluationRequest,
    OperationalStatus,
    ProgramOperationalAttestation,
    ScopeKind,
    ScopeRule,
    SemanticExclusionKind,
    TestDefinition,
    evaluate_test,
)
from astp.network_capabilities import builtin_network_capabilities
from astp.observation import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    HttpObservationEvidence,
    ObservationError,
    observe_http,
    verify_observation_evidence,
)
from astp.operator_review import ReviewDecision, record_operator_review
from astp.pentest_readiness import current_pentest_readiness
from astp.permit_broker import broker_queue_item_permit
from astp.permits import (
    DEFAULT_PERMIT_TTL_SECONDS,
    PermitVerificationRequest,
    SignedExecutionPermit,
    issue_execution_permit,
    policy_digest,
    verify_execution_permit,
)
from astp.planner import ObservationPlan, build_observation_plan
from astp.planner_state import get_planner_state, initialize_planner_state
from astp.policy_snapshot import capture_policy_snapshot
from astp.portable_assessment import export_portable_assessment, verify_portable_assessment
from astp.prioritization import prioritize_registry
from astp.program_catalog import (
    BugBountyWorkspace,
    ProgramSyncStatus,
    save_workspace,
    set_active_programs,
)
from astp.program_intake import (
    compile_program,
    import_program_file,
    import_program_text,
    resolve_issue_with_denies,
    resolve_issue_with_semantic_exclusion,
    resolve_rate_issue,
)
from astp.program_models import BugBountyProgram
from astp.program_runtime import create_operational_attestation
from astp.program_server import serve_program_intake
from astp.protocol_analyzers import analyze_protocol_posture
from astp.publication_bundle import build_publication_bundle, verify_publication_bundle
from astp.readiness import evaluate_assessment_readiness
from astp.report_finalization import ReportFinalization, finalize_report
from astp.reporting import render_markdown_report
from astp.result_interpreter import interpret_observation
from astp.resume_guard import evaluate_resume
from astp.retest_scheduler import build_retest_request
from astp.review_package import build_review_package
from astp.risk_context import AssetImportance, Exposure, RiskContext, score_finding_context
from astp.runtime_state import revoke_runtime_permit, runtime_permit_status
from astp.safe_assessment_profile import SafeAssessmentProfile
from astp.scope_compiler import CompilationStatus, compile_scope_file
from astp.security_graph import build_security_graph
from astp.session_budget import SessionBudget
from astp.session_journal import append_session_event, verify_session_journal
from astp.session_ledger import get_session_counters, initialize_session_ledger
from astp.session_report import summarize_session_execution
from astp.surface_mapper import build_surface_map
from astp.target_discovery import discover_targets_from_evidence
from astp.target_registry import (
    TargetRegistry,
    load_or_create_registry,
    merge_discovery,
    save_registry,
)
from astp.test_dsl import SecurityTestDefinition
from astp.verification_broker import (
    VerificationAuthorizationCandidate,
    broker_reviewed_verification,
)
from astp.verification_execution import prepare_verification_execution
from astp.verification_queue import list_verification_queue
from astp.verification_review import (
    VerificationReview,
    VerificationReviewDecision,
    review_verification_item,
)
from astp.web_posture import analyze_http_posture
from astp.work_queue import WorkQueue, build_fair_work_queue

app = typer.Typer(
    help=(
        "ASTP policy-first security testing platform. "
        "M5 adds bounded autonomous observation, policy-drift stops, durable budgets, "
        "and resumable evidence-driven sessions."
    )
)
console = Console()

DEFAULT_STATE_PATH = Path(".astp") / "permit-state.json"
DEFAULT_AUDIT_PATH = Path(".astp") / "audit.jsonl"
DEFAULT_RUNTIME_DB_PATH = Path(".astp") / "runtime.db"


@app.command("show-engagement")
def show_engagement(path: Path) -> None:
    """Validate and display a structured engagement YAML file."""
    engagement = load_model(path, Engagement)
    console.print(f"[bold]{engagement.name}[/bold] ({engagement.id})")
    console.print("\n[bold]Allowed scope[/bold]")

    for rule in engagement.scope.allowed:
        console.print(f"  + {rule.kind.value}: {rule.value}")

    console.print("\n[bold]Denied scope[/bold]")

    for rule in engagement.scope.denied:
        console.print(f"  - {rule.kind.value}: {rule.value}")

    console.print("\n[bold]Approval-required scope[/bold]")

    for rule in engagement.scope.approval_required:
        console.print(f"  ! {rule.kind.value}: {rule.value}")

    console.print(f"\nRate limit: {engagement.constraints.max_requests_per_second} req/s")


@app.command("compile-scope")
def compile_scope_command(
    source: Annotated[
        Path,
        typer.Argument(help="Plain-text bug bounty rules, SOW, or testing brief"),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the compiled Engagement YAML here"),
    ] = None,
    engagement_id: Annotated[
        str,
        typer.Option("--id", help="Engagement identifier"),
    ] = "compiled-engagement",
    engagement_name: Annotated[
        str,
        typer.Option("--name", help="Engagement display name"),
    ] = "Compiled Engagement",
) -> None:
    """Compile human-readable scope rules into a conservative structured engagement."""
    result = compile_scope_file(
        source,
        engagement_id=engagement_id,
        engagement_name=engagement_name,
    )

    table = Table(title="ASTP Scope Compiler")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Status", result.status.value.upper())
    table.add_row("Allowed assets", str(len(result.engagement.scope.allowed)))
    table.add_row("Denied assets", str(len(result.engagement.scope.denied)))
    table.add_row(
        "Approval-required assets",
        str(len(result.engagement.scope.approval_required)),
    )
    table.add_row("Extracted rules", str(len(result.extracted_rules)))
    table.add_row("Issues", str(len(result.issues)))
    table.add_row(
        "Rate limit",
        f"{result.engagement.constraints.max_requests_per_second} req/s",
    )
    console.print(table)

    if result.issues:
        console.print("\n[bold yellow]Review required[/bold yellow]")
        for issue in result.issues:
            console.print(f"- [{issue.severity.value}] {issue.code}: {issue.message}")
            if issue.source_text:
                console.print(f"  source: {issue.source_text}")

    if output is not None:
        dump_yaml(result.engagement, output)
        console.print(f"\nCompiled engagement written to: {output}")
    else:
        console.print("\n[bold]Compiled engagement[/bold]")
        console.print(dump_yaml(result.engagement), markup=False)

    if result.status == CompilationStatus.NEEDS_REVIEW:
        raise typer.Exit(code=2)


@app.command("authorize-test")
def authorize_test_command(
    engagement_path: Annotated[
        Path,
        typer.Argument(help="Engagement YAML"),
    ],
    test_path: Annotated[
        Path,
        typer.Argument(help="Test definition YAML"),
    ],
    target: Annotated[
        str,
        typer.Option("--target", help="Target URL/host"),
    ],
    context: Annotated[
        list[str] | None,
        typer.Option("--context", help="Available context item; repeatable"),
    ] = None,
    approval_path: Annotated[
        list[Path] | None,
        typer.Option("--approval", help="Approval artifact YAML; repeatable"),
    ] = None,
    http_method: Annotated[
        str | None,
        typer.Option("--http-method", help="HTTP method being authorized"),
    ] = None,
    identity: Annotated[
        str | None,
        typer.Option("--identity", help="Logical identity/role used by the test"),
    ] = None,
    requested_rps: Annotated[
        float | None,
        typer.Option("--rps", help="Requested maximum request rate"),
    ] = None,
    program_status_attestation: Annotated[
        Path | None,
        typer.Option(
            "--program-status-attestation",
            help="Fresh ProgramOperationalAttestation YAML for program online/offline gates",
        ),
    ] = None,
    semantic_clear: Annotated[
        list[str] | None,
        typer.Option(
            "--semantic-clear",
            help="Semantic exclusion rule ID explicitly reviewed as not matching the target",
        ),
    ] = None,
    semantic_match: Annotated[
        list[str] | None,
        typer.Option(
            "--semantic-match",
            help="Semantic exclusion rule ID explicitly identified as matching the target",
        ),
    ] = None,
) -> None:
    """Produce an auditable authorization decision without executing a test."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    approvals = [load_model(path, ApprovalArtifact) for path in (approval_path or [])]
    operational_attestation = (
        load_model(program_status_attestation, ProgramOperationalAttestation)
        if program_status_attestation is not None
        else None
    )
    result = authorize_test(
        engagement,
        test,
        AuthorizationRequest(
            target=target,
            available_context=set(context or []),
            approvals=approvals,
            http_method=http_method,
            identity=identity,
            requested_requests_per_second=requested_rps,
            program_operational_attestation=operational_attestation,
            semantic_exclusion_clears=set(semantic_clear or []),
            semantic_exclusion_matches=set(semantic_match or []),
        ),
    )

    table = Table(title="ASTP Authorization Decision")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Reason")
    for check in result.checks:
        table.add_row(check.name, check.status.value.upper(), check.message)
    console.print(table)
    console.print(f"\nDecision: [bold]{result.decision.value.upper()}[/bold]")
    # authorize-test
    console.print("Execution: NOT PERFORMED (authorization only)")
    if result.approval_ids:
        console.print(f"Approval artifacts: {', '.join(result.approval_ids)}")
    if result.effective_max_requests_per_second is not None:
        rate = result.effective_max_requests_per_second
        console.print(f"Effective rate limit: {rate:g} req/s")
    if result.missing_context:
        console.print(f"Missing context: {', '.join(result.missing_context)}")


def _permit_keyring() -> tuple[str, dict[str, str]]:
    serialized = os.environ.get("ASTP_PERMIT_KEYS")
    active_key_id = os.environ.get("ASTP_PERMIT_ACTIVE_KEY_ID", "local-v1")
    if serialized:
        try:
            raw = json.loads(serialized)
        except json.JSONDecodeError as exc:
            raise typer.BadParameter("ASTP_PERMIT_KEYS must be a JSON object.") from exc
        if not isinstance(raw, dict) or not all(
            isinstance(key_id, str) and isinstance(value, str) for key_id, value in raw.items()
        ):
            raise typer.BadParameter("ASTP_PERMIT_KEYS must map key IDs to string secrets.")
        keys = dict(raw)
    else:
        legacy = os.environ.get("ASTP_PERMIT_KEY")
        if not legacy:
            raise typer.BadParameter(
                "ASTP_PERMIT_KEY or ASTP_PERMIT_KEYS is required; keys must contain "
                "at least 32 bytes."
            )
        keys = {active_key_id: legacy}
    if active_key_id not in keys:
        raise typer.BadParameter(
            f"Active permit key ID {active_key_id!r} is not present in the keyring."
        )
    return active_key_id, keys


@app.command("issue-permit")
def issue_permit_command(
    engagement_path: Annotated[
        Path,
        typer.Argument(help="Engagement YAML"),
    ],
    test_path: Annotated[
        Path,
        typer.Argument(help="Test definition YAML"),
    ],
    target: Annotated[
        str,
        typer.Option("--target", help="Exact target URL/host to bind"),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Write the signed permit YAML here"),
    ],
    context: Annotated[
        list[str] | None,
        typer.Option("--context", help="Available context item; repeatable"),
    ] = None,
    approval_path: Annotated[
        list[Path] | None,
        typer.Option("--approval", help="Approval artifact YAML; repeatable"),
    ] = None,
    http_method: Annotated[
        str | None,
        typer.Option("--http-method", help="HTTP method to bind"),
    ] = None,
    identity: Annotated[
        str | None,
        typer.Option("--identity", help="Logical identity/role to bind"),
    ] = None,
    requested_rps: Annotated[
        float | None,
        typer.Option("--rps", help="Requested maximum request rate"),
    ] = None,
    program_status_attestation: Annotated[
        Path | None,
        typer.Option(
            "--program-status-attestation",
            help="Fresh ProgramOperationalAttestation YAML for program online/offline gates",
        ),
    ] = None,
    semantic_clear: Annotated[
        list[str] | None,
        typer.Option(
            "--semantic-clear",
            help="Semantic exclusion rule ID explicitly reviewed as not matching the target",
        ),
    ] = None,
    semantic_match: Annotated[
        list[str] | None,
        typer.Option(
            "--semantic-match",
            help="Semantic exclusion rule ID explicitly identified as matching the target",
        ),
    ] = None,
    ttl_seconds: Annotated[
        int,
        typer.Option("--ttl-seconds", help="Permit lifetime in seconds; maximum 900"),
    ] = DEFAULT_PERMIT_TTL_SECONDS,
    audit_path: Annotated[
        Path,
        typer.Option("--audit", help="Append-only audit log"),
    ] = DEFAULT_AUDIT_PATH,
) -> None:
    """Authorize an exact action and issue a short-lived signed execution permit."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    approvals = [load_model(path, ApprovalArtifact) for path in (approval_path or [])]
    operational_attestation = (
        load_model(program_status_attestation, ProgramOperationalAttestation)
        if program_status_attestation is not None
        else None
    )
    request = AuthorizationRequest(
        target=target,
        available_context=set(context or []),
        approvals=approvals,
        http_method=http_method,
        identity=identity,
        requested_requests_per_second=requested_rps,
        program_operational_attestation=operational_attestation,
        semantic_exclusion_clears=set(semantic_clear or []),
        semantic_exclusion_matches=set(semantic_match or []),
    )
    authorization = authorize_test(engagement, test, request)
    if authorization.decision != Decision.ALLOW:
        console.print(
            f"Authorization decision: [bold]{authorization.decision.value.upper()}[/bold]"
        )
        console.print("Permit not issued.")
        raise typer.Exit(code=2)

    active_key_id, keys = _permit_keyring()
    try:
        permit = issue_execution_permit(
            engagement,
            test,
            request,
            keys[active_key_id],
            ttl_seconds=ttl_seconds,
            key_id=active_key_id,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    dump_yaml(permit, output)
    append_audit_event(
        audit_path,
        "permit.issued",
        permit_id=permit.payload.permit_id,
        details={
            "key_id": permit.payload.key_id,
            "engagement_id": permit.payload.engagement_id,
            "test_id": permit.payload.test_id,
            "target": permit.payload.target,
            "expires_at": permit.payload.expires_at.isoformat(),
            "operational_attestation_id": permit.payload.operational_attestation_id,
        },
    )
    console.print("[bold green]Execution permit issued.[/bold green]")
    console.print(f"Permit ID: {permit.payload.permit_id}")
    console.print(f"Expires at: {permit.payload.expires_at.isoformat()}")
    console.print(f"Maximum rate: {permit.payload.max_requests_per_second:g} req/s")
    console.print(f"Written to: {output}")
    console.print("Permit issuance does not execute a network action.")


@app.command("verify-permit")
def verify_permit_command(
    permit_path: Annotated[
        Path,
        typer.Argument(help="Signed execution permit YAML"),
    ],
    engagement_path: Annotated[
        Path,
        typer.Argument(help="Current engagement YAML"),
    ],
    test_path: Annotated[
        Path,
        typer.Argument(help="Current test definition YAML"),
    ],
    target: Annotated[
        str,
        typer.Option("--target", help="Exact target URL/host being requested"),
    ],
    http_method: Annotated[
        str | None,
        typer.Option("--http-method", help="HTTP method being requested"),
    ] = None,
    identity: Annotated[
        str | None,
        typer.Option("--identity", help="Logical identity/role being requested"),
    ] = None,
    requested_rps: Annotated[
        float | None,
        typer.Option("--rps", help="Requested maximum request rate"),
    ] = None,
) -> None:
    """Verify a signed permit against current policy and an exact requested action."""
    permit = load_model(permit_path, SignedExecutionPermit)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    try:
        result = verify_execution_permit(
            permit,
            engagement,
            test,
            PermitVerificationRequest(
                target=target,
                http_method=http_method,
                identity=identity,
                requested_requests_per_second=requested_rps,
            ),
            _permit_keyring()[1],
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    table = Table(title="ASTP Execution Permit Verification")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Reason")
    for check in result.checks:
        table.add_row(check.name, check.status.value.upper(), check.message)
    console.print(table)
    console.print(f"\nPermit valid: [bold]{'YES' if result.valid else 'NO'}[/bold]")
    console.print("Verification only; no network action was performed.")
    if not result.valid:
        raise typer.Exit(code=3)


@app.command("consume-permit")
def consume_permit_command(
    permit_path: Annotated[Path, typer.Argument(help="Signed execution permit YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Current test definition YAML")],
    target: Annotated[str, typer.Option("--target", help="Exact target URL/host")],
    http_method: Annotated[
        str | None, typer.Option("--http-method", help="HTTP method being requested")
    ] = None,
    identity: Annotated[
        str | None, typer.Option("--identity", help="Logical identity/role")
    ] = None,
    requested_rps: Annotated[
        float | None, typer.Option("--rps", help="Requested maximum request rate")
    ] = None,
    state_path: Annotated[
        Path, typer.Option("--state", help="Permit lifecycle state file")
    ] = DEFAULT_STATE_PATH,
    audit_path: Annotated[
        Path, typer.Option("--audit", help="Append-only audit log")
    ] = DEFAULT_AUDIT_PATH,
) -> None:
    """Verify and consume a permit exactly once; no network action is executed."""
    permit = load_model(permit_path, SignedExecutionPermit)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    _, keys = _permit_keyring()
    result = consume_execution_permit(
        permit,
        engagement,
        test,
        PermitVerificationRequest(
            target=target,
            http_method=http_method,
            identity=identity,
            requested_requests_per_second=requested_rps,
        ),
        keys,
        state_path,
    )
    append_audit_event(
        audit_path,
        "permit.consumed" if result.accepted else "permit.consume_rejected",
        permit_id=permit.payload.permit_id,
        details={
            "accepted": result.accepted,
            "status": result.lifecycle_status.value,
            "message": result.message,
        },
    )
    console.print(f"Permit consumed: [bold]{'YES' if result.accepted else 'NO'}[/bold]")
    console.print(f"Lifecycle status: {result.lifecycle_status.value.upper()}")
    console.print(result.message)
    console.print("Permit lifecycle operation only; no network action was performed.")
    if not result.accepted:
        raise typer.Exit(code=4)


@app.command("revoke-permit")
def revoke_permit_command(
    permit_id: Annotated[str, typer.Argument(help="Permit ID to revoke")],
    reason: Annotated[str, typer.Option("--reason", help="Human-readable revocation reason")],
    state_path: Annotated[
        Path, typer.Option("--state", help="Permit lifecycle state file")
    ] = DEFAULT_STATE_PATH,
    audit_path: Annotated[
        Path, typer.Option("--audit", help="Append-only audit log")
    ] = DEFAULT_AUDIT_PATH,
) -> None:
    """Revoke a permit before it is consumed."""
    try:
        entry = revoke_permit(state_path, permit_id, reason=reason)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    append_audit_event(
        audit_path,
        "permit.revoked",
        permit_id=permit_id,
        details={"reason": reason},
    )
    console.print(f"Permit {permit_id} status: {entry.status.value.upper()}")


@app.command("permit-status")
def permit_status_command(
    permit_id: Annotated[str, typer.Argument(help="Permit ID")],
    state_path: Annotated[
        Path, typer.Option("--state", help="Permit lifecycle state file")
    ] = DEFAULT_STATE_PATH,
) -> None:
    """Show local lifecycle state for a permit."""
    console.print(permit_status(state_path, permit_id).value.upper())


@app.command("runtime-permit-status")
def runtime_permit_status_command(
    permit_id: Annotated[str, typer.Argument(help="Permit ID")],
    runtime_db_path: Annotated[
        Path, typer.Option("--runtime-db", help="Transactional worker runtime database")
    ] = DEFAULT_RUNTIME_DB_PATH,
) -> None:
    """Show permit state from the transactional worker runtime database."""
    console.print(runtime_permit_status(runtime_db_path, permit_id).value.upper())


@app.command("revoke-runtime-permit")
def revoke_runtime_permit_command(
    permit_id: Annotated[str, typer.Argument(help="Permit ID to revoke")],
    reason: Annotated[str, typer.Option("--reason", help="Human-readable revocation reason")],
    runtime_db_path: Annotated[
        Path, typer.Option("--runtime-db", help="Transactional worker runtime database")
    ] = DEFAULT_RUNTIME_DB_PATH,
    audit_path: Annotated[
        Path, typer.Option("--audit", help="Append-only audit log")
    ] = DEFAULT_AUDIT_PATH,
) -> None:
    """Revoke a permit in the transactional worker runtime database."""
    try:
        status = revoke_runtime_permit(runtime_db_path, permit_id, reason=reason)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    append_audit_event(
        audit_path,
        "permit.runtime_revoked",
        permit_id=permit_id,
        details={"reason": reason},
    )
    console.print(f"Permit {permit_id} status: {status.value.upper()}")


@app.command("verify-audit")
def verify_audit_command(
    audit_path: Annotated[Path, typer.Argument(help="Audit JSONL file")],
) -> None:
    """Verify the local hash-linked audit chain."""
    try:
        valid, message = verify_audit_chain(audit_path)
    except ValueError as exc:
        console.print(f"Audit chain valid: [bold]NO[/bold]\n{exc}")
        raise typer.Exit(code=5) from exc
    console.print(f"Audit chain valid: [bold]{'YES' if valid else 'NO'}[/bold]")
    console.print(message)
    if not valid:
        raise typer.Exit(code=5)


@app.command("observe-http")
def observe_http_command(
    permit_path: Annotated[Path, typer.Argument(help="Signed execution permit YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Current test definition YAML")],
    target: Annotated[str, typer.Option("--target", help="Exact HTTP(S) target URL")],
    http_method: Annotated[
        str, typer.Option("--http-method", help="Observation method: GET or HEAD")
    ] = "GET",
    identity: Annotated[
        str | None, typer.Option("--identity", help="Logical identity/role")
    ] = None,
    requested_rps: Annotated[
        float | None, typer.Option("--rps", help="Requested maximum request rate")
    ] = None,
    state_path: Annotated[
        Path, typer.Option("--state", help="Permit lifecycle state file")
    ] = DEFAULT_STATE_PATH,
    audit_path: Annotated[
        Path, typer.Option("--audit", help="Append-only audit log")
    ] = DEFAULT_AUDIT_PATH,
    evidence_path: Annotated[
        Path | None,
        typer.Option("--evidence", help="Write observation evidence JSON here"),
    ] = None,
    manifest_path: Annotated[
        Path, typer.Option("--manifest", help="Evidence manifest JSONL")
    ] = Path(".astp")
    / "evidence-manifest.jsonl",
    rate_state_path: Annotated[
        Path, typer.Option("--rate-state", help="Durable rate-limit state file")
    ] = Path(".astp")
    / "rate-state.json",
    runtime_db_path: Annotated[
        Path,
        typer.Option(
            "--runtime-db",
            help="Transactional worker runtime database",
        ),
    ] = DEFAULT_RUNTIME_DB_PATH,
    sensitivity: Annotated[
        SensitivityLabel, typer.Option("--sensitivity", help="Evidence sensitivity label")
    ] = SensitivityLabel.INTERNAL,
    timeout_seconds: Annotated[
        float, typer.Option("--timeout", help="Network timeout in seconds; maximum 30")
    ] = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: Annotated[
        int,
        typer.Option(
            "--max-body-bytes",
            help="Maximum response body bytes captured; maximum 1048576",
        ),
    ] = DEFAULT_MAX_BODY_BYTES,
) -> None:
    """Perform one permit-gated GET/HEAD observation and write redacted evidence."""
    permit = load_model(permit_path, SignedExecutionPermit)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    _, keys = _permit_keyring()
    output = evidence_path or (Path(".astp") / "evidence" / f"{permit.payload.permit_id}.json")
    try:
        result = observe_http(
            permit,
            engagement,
            test,
            keys,
            target=target,
            method=http_method,
            identity=identity,
            requested_rps=requested_rps,
            state_path=state_path,
            audit_path=audit_path,
            evidence_path=output,
            manifest_path=manifest_path,
            rate_state_path=rate_state_path,
            runtime_db_path=runtime_db_path,
            sensitivity=sensitivity,
            timeout_seconds=timeout_seconds,
            max_body_bytes=max_body_bytes,
        )
    except ObservationError as exc:
        console.print(f"Observation completed: [bold]NO[/bold]\n{exc}")
        raise typer.Exit(code=6) from exc

    evidence = result.evidence
    table = Table(title="ASTP HTTP Observation")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Method", evidence.method)
    table.add_row("Target", evidence.target)
    table.add_row("Status", str(evidence.status_code))
    table.add_row("Captured body", f"{evidence.body_bytes_captured} bytes")
    table.add_row("Body truncated", "YES" if evidence.body_truncated else "NO")
    table.add_row("Evidence ID", evidence.evidence_id)
    table.add_row("Action ID", evidence.action_id)
    table.add_row("Sensitivity", evidence.sensitivity.value)
    table.add_row("Evidence hash", evidence.evidence_hash)
    table.add_row("Evidence", str(result.evidence_path))
    table.add_row("Manifest", str(result.manifest_path))
    if evidence.redirect is not None:
        table.add_row("Redirect", evidence.redirect.target)
        table.add_row("Redirect followed", "NO")
        table.add_row("Redirect in scope", "YES" if evidence.redirect.in_scope else "NO")
    console.print(table)
    console.print("Permit consumed: [bold]YES[/bold]")
    console.print("Network execution: observation-only GET/HEAD (permit-gated worker)")


@app.command("verify-evidence")
def verify_evidence_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
) -> None:
    """Verify the canonical SHA-256 hash of stored observation evidence."""
    try:
        evidence = HttpObservationEvidence.model_validate_json(
            evidence_path.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        console.print(f"Evidence valid: [bold]NO[/bold]\n{exc}")
        raise typer.Exit(code=7) from exc
    valid = verify_observation_evidence(evidence)
    console.print(f"Evidence valid: [bold]{'YES' if valid else 'NO'}[/bold]")
    console.print(f"Evidence hash: {evidence.evidence_hash}")
    if not valid:
        raise typer.Exit(code=7)


@app.command("verify-evidence-manifest")
def verify_evidence_manifest_command(
    manifest_path: Annotated[Path, typer.Argument(help="Evidence manifest JSONL")],
    skip_artifacts: Annotated[
        bool, typer.Option("--skip-artifacts", help="Verify chain only, not artifact hashes")
    ] = False,
) -> None:
    """Verify the hash-linked evidence manifest and, by default, all artifacts."""
    try:
        valid, message = verify_evidence_manifest(
            manifest_path, verify_artifacts=not skip_artifacts
        )
    except (OSError, ValueError) as exc:
        console.print(f"Evidence manifest valid: [bold]NO[/bold]\n{exc}")
        raise typer.Exit(code=8) from exc
    console.print(f"Evidence manifest valid: [bold]{'YES' if valid else 'NO'}[/bold]")
    console.print(message)
    if not valid:
        raise typer.Exit(code=8)


@app.command("export-evidence-bundle")
def export_evidence_bundle_command(
    manifest_path: Annotated[Path, typer.Argument(help="Evidence manifest JSONL")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Write portable evidence bundle ZIP here")
    ],
) -> None:
    """Export a verified evidence manifest and its artifacts as a portable bundle."""
    try:
        receipt = export_evidence_bundle(manifest_path, output)
    except (OSError, ValueError) as exc:
        console.print(f"Evidence bundle exported: [bold]NO[/bold]\n{exc}")
        raise typer.Exit(code=9) from exc
    console.print("Evidence bundle exported: [bold]YES[/bold]")
    console.print(f"Bundle ID: {receipt.bundle_id}")
    console.print(f"Artifacts: {len(receipt.artifacts)}")
    console.print(f"Receipt hash: {receipt.receipt_hash}")
    console.print(f"Written to: {output}")


@app.command("verify-evidence-bundle")
def verify_evidence_bundle_command(
    bundle_path: Annotated[Path, typer.Argument(help="Portable evidence bundle ZIP")],
) -> None:
    """Verify a portable evidence bundle receipt, manifest snapshot, and artifacts."""
    valid, message = verify_evidence_bundle(bundle_path)
    console.print(f"Evidence bundle valid: [bold]{'YES' if valid else 'NO'}[/bold]")
    console.print(message)
    if not valid:
        raise typer.Exit(code=9)


@app.command("browser-intake-server")
def browser_intake_server_command(
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Write the latest browser capture JSON here"),
    ] = Path(".astp")
    / "browser-capture.json",
    platform: Annotated[
        str,
        typer.Option("--platform", help="Authenticated bug bounty platform identifier"),
    ] = "bughunt",
    catalog: Annotated[
        Path,
        typer.Option("--catalog", help="Persistent program catalog YAML"),
    ] = Path(".astp")
    / "program-catalog.yaml",
    captures_dir: Annotated[
        Path,
        typer.Option("--captures-dir", help="Raw authenticated program captures"),
    ] = Path(".astp")
    / "program-captures",
    programs_dir: Annotated[
        Path,
        typer.Option("--programs-dir", help="Normalized program YAML directory"),
    ] = Path("programs"),
    port: Annotated[
        int,
        typer.Option("--port", help="Loopback port used by the browser companion"),
    ] = 8765,
) -> None:
    """Serve authenticated program discovery and intake on loopback only."""
    if port < 1024 or port > 65535:
        raise typer.BadParameter("port must be between 1024 and 65535")
    intake_token = secrets.token_urlsafe(24)
    console.print(f"ASTP browser intake listening on http://127.0.0.1:{port}")
    console.print(f"Platform: {platform}")
    console.print(f"Latest capture: {output}")
    console.print(f"Program catalog: {catalog}")
    console.print("Intake token (paste into the browser companion):")
    console.print(intake_token, markup=False)
    serve_program_intake(
        intake_token=intake_token,
        platform=platform,
        latest_capture_path=output,
        catalog_path=catalog,
        captures_dir=captures_dir,
        programs_dir=programs_dir,
        port=port,
    )


@app.command("programs")
def programs_command(
    catalog: Annotated[
        Path,
        typer.Option("--catalog", help="Program catalog YAML"),
    ] = Path(".astp")
    / "program-catalog.yaml",
) -> None:
    """Display discovered bug bounty programs and their synchronization state."""
    if not catalog.exists():
        console.print(
            "[yellow]No program catalog found. Run authenticated discovery first.[/yellow]"
        )
        raise typer.Exit(code=2)
    workspace = load_model(catalog, BugBountyWorkspace)
    table = Table(title=f"ASTP Programs — {workspace.platform}")
    table.add_column("#", justify="right")
    table.add_column("Active")
    table.add_column("Program")
    table.add_column("Status")
    table.add_column("ID")
    for index, item in enumerate(workspace.programs, start=1):
        display_status = (
            "READY"
            if item.sync_status in {ProgramSyncStatus.SYNCED, ProgramSyncStatus.READY}
            else item.sync_status.value.upper()
        )
        table.add_row(
            str(index),
            "YES" if item.active else "",
            item.candidate.name,
            display_status,
            item.candidate.id,
        )
    console.print(table)
    console.print(f"Active programs: {len(workspace.active_programs())}")


@app.command("select-programs")
def select_programs_command(
    program_id: Annotated[
        list[str] | None,
        typer.Option("--id", help="Program ID to activate; repeatable"),
    ] = None,
    catalog: Annotated[
        Path,
        typer.Option("--catalog", help="Program catalog YAML"),
    ] = Path(".astp")
    / "program-catalog.yaml",
) -> None:
    """Select one or more synchronized programs as active workspace programs."""
    workspace = load_model(catalog, BugBountyWorkspace)
    selected = set(program_id or [])
    if not selected:
        table = Table(title="Select active bug bounty programs")
        table.add_column("#", justify="right")
        table.add_column("Program")
        table.add_column("Status")
        selectable: list[str] = []
        for index, item in enumerate(workspace.programs, start=1):
            table.add_row(str(index), item.candidate.name, item.sync_status.value.upper())
            selectable.append(item.candidate.id)
        console.print(table)
        raw = typer.prompt("Program numbers, comma-separated (for example 1,3)")
        try:
            indexes = {int(value.strip()) for value in raw.split(",") if value.strip()}
        except ValueError as exc:
            raise typer.BadParameter("selection must contain program numbers") from exc
        if any(index < 1 or index > len(selectable) for index in indexes):
            raise typer.BadParameter("selection contains an unknown program number")
        selected = {selectable[index - 1] for index in indexes}

    unavailable = {
        item.candidate.id
        for item in workspace.programs
        if item.candidate.id in selected and item.sync_status == ProgramSyncStatus.FAILED
    }
    if unavailable:
        raise typer.BadParameter("cannot activate failed programs: " + ", ".join(unavailable))
    set_active_programs(workspace, selected)
    save_workspace(workspace, catalog)
    console.print("Active programs updated:")
    for item in workspace.active_programs():
        console.print(f"  + {item.candidate.name} ({item.candidate.id})")


@app.command("import-program")
def import_program_command(
    source: Annotated[Path, typer.Argument(help="Markdown/text/HTML or browser capture JSON")],
    name: Annotated[str, typer.Option("--name", help="Bug bounty program name")],
    platform: Annotated[str, typer.Option("--platform", help="Program platform, e.g. bughunt")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Write normalized BugBountyProgram YAML here"),
    ],
    browser_capture: Annotated[
        bool,
        typer.Option("--browser-capture", help="Treat source as an ASTP browser capture JSON"),
    ] = False,
) -> None:
    """Normalize a program source while preserving provenance and unresolved rules."""
    if browser_capture:
        capture = load_capture(source)
        program = import_program_text(
            capture_to_text(capture),
            name=name,
            platform=platform,
            source_type="authenticated_browser",
            source_url=capture.url,
            captured_at=capture.captured_at,
        )
        program.source.title = capture.title
    else:
        program = import_program_file(source, name=name, platform=platform)

    dump_yaml(program, output)
    table = Table(title="ASTP Bug Bounty Program Intake")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Program", program.name)
    table.add_row("Platform", program.platform)
    table.add_row("Status", program.status.value.upper())
    table.add_row("Allowed scope", str(len(program.allowed_scope())))
    table.add_row("Denied scope", str(len(program.denied_scope())))
    table.add_row("Constraints", str(len(program.constraints)))
    table.add_row("Review issues", str(len(program.issues)))
    console.print(table)
    for issue in program.issues:
        console.print(f"- [yellow]{issue.code}[/yellow]: {issue.message}")
    console.print(f"Normalized program written to: {output}")


def _parse_review_deny(value: str) -> ScopeRule:
    try:
        raw_kind, raw_value = value.split("=", 1)
        kind = ScopeKind(raw_kind.strip())
    except (ValueError, KeyError) as exc:
        raise typer.BadParameter(
            "deny mappings must use KIND=VALUE, for example wildcard_domain=*.example.com"
        ) from exc
    raw_value = raw_value.strip()
    if not raw_value:
        raise typer.BadParameter("deny mapping value cannot be empty")
    return ScopeRule(kind=kind, value=raw_value)


@app.command("review-program")
def review_program_command(
    program_id: Annotated[
        str,
        typer.Argument(help="Catalog program ID to review"),
    ],
    catalog: Annotated[
        Path,
        typer.Option("--catalog", help="Program catalog YAML"),
    ] = Path(".astp")
    / "program-catalog.yaml",
    rate: Annotated[
        float | None,
        typer.Option(
            "--rps",
            help=(
                "Operator-selected conservative RPS for qualitative traffic restrictions; "
                "this is recorded as an operator decision, not a program-published limit"
            ),
        ),
    ] = None,
    issue_index: Annotated[
        int | None,
        typer.Option("--issue", help="1-based review issue number to resolve with deny mappings"),
    ] = None,
    deny: Annotated[
        list[str] | None,
        typer.Option(
            "--deny",
            help="Reviewed deny mapping KIND=VALUE; repeat for multiple mappings",
        ),
    ] = None,
    semantic_deny: Annotated[
        str | None,
        typer.Option(
            "--semantic-deny",
            help=(
                "Semantic deny guardrail KIND=VALUE; kinds: product_family, "
                "organization_family, asset_family"
            ),
        ),
    ] = None,
    note: Annotated[
        str | None,
        typer.Option("--note", help="Operator review note stored with the resolution"),
    ] = None,
) -> None:
    """Review blocking policy ambiguities without inventing program rules."""
    workspace = load_model(catalog, BugBountyWorkspace)
    item = next(
        (entry for entry in workspace.programs if entry.candidate.id == program_id),
        None,
    )
    if item is None:
        raise typer.BadParameter(f"unknown catalog program ID: {program_id}")
    if not item.normalized_path:
        raise typer.BadParameter("program has not been normalized yet")

    program_path = Path(item.normalized_path)
    program = load_model(program_path, BugBountyProgram)
    if program.id != item.candidate.id:
        program.id = item.candidate.id

    changed = False
    if rate is not None:
        try:
            resolve_rate_issue(program, rate)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        changed = True

    if issue_index is not None and semantic_deny is not None:
        if deny:
            raise typer.BadParameter("use either --semantic-deny or --deny, not both")
        try:
            raw_kind, raw_value = semantic_deny.split("=", 1)
            semantic_kind = SemanticExclusionKind(raw_kind.strip())
        except ValueError as exc:
            raise typer.BadParameter(
                "semantic deny must use KIND=VALUE; kinds: product_family, "
                "organization_family, asset_family"
            ) from exc
        try:
            resolve_issue_with_semantic_exclusion(
                program,
                issue_index=issue_index,
                kind=semantic_kind,
                value=raw_value,
                note=note,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        changed = True
    elif issue_index is not None:
        deny_rules = [_parse_review_deny(value) for value in (deny or [])]
        try:
            resolve_issue_with_denies(
                program,
                issue_index=issue_index,
                deny_rules=deny_rules,
                note=note,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc
        changed = True
    elif deny or semantic_deny:
        raise typer.BadParameter("--deny/--semantic-deny requires --issue")

    if changed:
        dump_yaml(program, program_path)
        item.sync_status = (
            ProgramSyncStatus.NEEDS_REVIEW if program.unresolved_issues else ProgramSyncStatus.READY
        )
        save_workspace(workspace, catalog)

    table = Table(title=f"ASTP Policy Review — {program.name}")
    table.add_column("#", justify="right")
    table.add_column("State")
    table.add_column("Code")
    table.add_column("Source")
    for index, issue in enumerate(program.issues, start=1):
        state = "RESOLVED" if issue.resolved else "BLOCKING"
        table.add_row(index.__str__(), state, issue.code, issue.source_text or "")
    console.print(table)
    console.print(f"Policy status: {program.status.value.upper()}")
    if program.reviewed_max_requests_per_second is not None:
        console.print(
            "Reviewed execution rate: "
            f"{program.reviewed_max_requests_per_second:g} req/s [operator decision]"
        )
    if program.semantic_exclusions:
        console.print("Semantic deny guardrails:")
        for rule in program.semantic_exclusions:
            console.print(f"- {rule.id}: {rule.kind.value}={rule.value}")
    if program.unresolved_issues:
        console.print(
            "[yellow]Execution remains blocked until every blocking issue has a safe, "
            "explicit resolution.[/yellow]"
        )


@app.command("attest-program-status")
def attest_program_status_command(
    program_path: Annotated[
        Path,
        typer.Argument(help="Normalized BugBountyProgram YAML"),
    ],
    status: Annotated[
        OperationalStatus,
        typer.Option("--status", help="Observed current program status"),
    ],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Write ProgramOperationalAttestation YAML here"),
    ],
    source_type: Annotated[
        str,
        typer.Option(
            "--source",
            help="How current status was observed (for example operator or authenticated_browser)",
        ),
    ] = "operator",
    note: Annotated[
        str | None,
        typer.Option("--note", help="Optional observation note"),
    ] = None,
) -> None:
    """Record a short-lived operational-status attestation bound to a program revision."""
    program = load_model(program_path, BugBountyProgram)
    try:
        attestation = create_operational_attestation(
            program,
            status=status,
            source_type=source_type,
            note=note,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    dump_yaml(attestation, output)
    console.print(f"Program status attestation written to: {output}")
    console.print(f"Attestation ID: {attestation.id}")
    console.print(f"Status: {attestation.status.value.upper()}")
    console.print(f"Observed at: {attestation.observed_at.isoformat()}")


@app.command("compile-program")
def compile_program_command(
    program_path: Annotated[Path, typer.Argument(help="Normalized BugBountyProgram YAML")],
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Write executable Engagement YAML here"),
    ],
    max_requests_per_second: Annotated[
        float | None,
        typer.Option("--rps", help="Explicitly reviewed numeric execution rate"),
    ] = None,
) -> None:
    """Compile a reviewed program into an executable ASTP engagement."""
    program = load_model(program_path, BugBountyProgram)
    try:
        engagement = compile_program(
            program,
            max_requests_per_second=max_requests_per_second,
        )
    except ValueError as exc:
        console.print(f"[bold yellow]Compilation blocked:[/bold yellow] {exc}")
        raise typer.Exit(code=2) from exc
    dump_yaml(engagement, output)
    console.print(f"Executable engagement written to: {output}")


@app.command("discover-targets")
def discover_targets_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Write discovered target candidates YAML here")
    ],
    include_links: Annotated[
        bool, typer.Option("--links/--no-links", help="Extract bounded links from body preview")
    ] = True,
    max_links: Annotated[
        int, typer.Option("--max-links", help="Maximum body-preview link candidates")
    ] = 50,
) -> None:
    """Derive non-executing redirect/link candidates from existing observation evidence."""
    if max_links < 0 or max_links > 500:
        raise typer.BadParameter("max-links must be between 0 and 500")
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    engagement = load_model(engagement_path, Engagement)
    result = discover_targets_from_evidence(
        evidence,
        engagement,
        include_links=include_links,
        max_link_candidates=max_links,
    )
    dump_yaml(result, output)
    table = Table(title="ASTP Evidence-Derived Target Discovery")
    table.add_column("Kind")
    table.add_column("Safety")
    table.add_column("In scope")
    table.add_column("Target")
    for candidate in result.candidates:
        table.add_row(
            candidate.kind.value,
            candidate.safety.value.upper(),
            "YES" if candidate.in_scope else "NO",
            candidate.display_target,
        )
    console.print(table)
    console.print(f"Candidates: {len(result.candidates)}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("merge-targets")
def merge_targets_command(
    discovery_path: Annotated[Path, typer.Argument(help="Target discovery YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    registry_path: Annotated[
        Path, typer.Option("--registry", help="Persistent target registry YAML")
    ] = Path(".astp")
    / "target-registry.yaml",
) -> None:
    """Merge discovered candidates into a deduplicated provenance-preserving registry."""
    from astp.target_discovery import TargetDiscoveryResult

    engagement = load_model(engagement_path, Engagement)
    discovery = load_model(discovery_path, TargetDiscoveryResult)
    try:
        registry = load_or_create_registry(registry_path, engagement.id)
        merge_discovery(registry, discovery)
        save_registry(registry, registry_path)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Registry entries: {len(registry.entries)}")
    console.print(f"Written to: {registry_path}")
    console.print("Network execution: NOT PERFORMED")


@app.command("plan-observations")
def plan_observations_command(
    registry_path: Annotated[Path, typer.Argument(help="Target registry YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Observation test definition YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write observation plan YAML")],
    semantic_clear: Annotated[
        list[str] | None,
        typer.Option("--semantic-clear", help="Semantic exclusion reviewed clear; repeatable"),
    ] = None,
    program_status_attestation: Annotated[
        Path | None,
        typer.Option("--program-status-attestation", help="Fresh program-status attestation YAML"),
    ] = None,
    requested_rps: Annotated[
        float | None, typer.Option("--rps", help="Requested rate used for policy evaluation")
    ] = None,
) -> None:
    """Build a deterministic policy-evaluated plan; it never issues permits or executes."""
    registry = load_model(registry_path, TargetRegistry)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    attestation = (
        load_model(program_status_attestation, ProgramOperationalAttestation)
        if program_status_attestation is not None
        else None
    )
    plan = build_observation_plan(
        registry,
        engagement,
        test,
        semantic_exclusion_clears=set(semantic_clear or []),
        operational_attestation=attestation,
        requested_rps=requested_rps,
    )
    dump_yaml(plan, output)
    table = Table(title="ASTP Deterministic Observation Plan")
    table.add_column("ID")
    table.add_column("Status")
    table.add_column("Target")
    for item in plan.items:
        table.add_row(item.id, item.status.value.upper(), item.target)
    console.print(table)
    console.print("Permits issued: 0")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("build-work-queue")
def build_work_queue_command(
    plan_paths: Annotated[
        list[Path], typer.Argument(help="One or more observation plan YAML files")
    ],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write work queue YAML")],
    max_active_programs: Annotated[
        int, typer.Option("--max-active-programs", help="Maximum programs represented in queue")
    ] = 4,
    max_items: Annotated[
        int, typer.Option("--max-items", help="Maximum authorizable items in queue")
    ] = 100,
) -> None:
    """Build a fair multi-program control-plane queue; no permits or network actions occur."""
    plans = [load_model(path, ObservationPlan) for path in plan_paths]
    try:
        queue = build_fair_work_queue(
            plans,
            max_active_programs=max_active_programs,
            max_items=max_items,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    dump_yaml(queue, output)
    table = Table(title="ASTP Multi-Program Work Queue")
    table.add_column("Queue")
    table.add_column("Engagement")
    table.add_column("Target")
    for item in queue.items:
        table.add_row(item.queue_id, item.engagement_id, item.target)
    console.print(table)
    console.print(f"Items: {len(queue.items)}")
    console.print("Every item still requires its own signed execution permit.")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("validate-test-dsl")
def validate_test_dsl_command(
    path: Annotated[Path, typer.Argument(help="Security Test DSL YAML")],
    runtime_output: Annotated[
        Path | None,
        typer.Option(
            "--runtime-output",
            help="Optionally write compatible runtime TestDefinition YAML",
        ),
    ] = None,
) -> None:
    """Validate Security Test DSL v0.1 without executing the test."""
    definition = load_model(path, SecurityTestDefinition)
    console.print("Test DSL valid: YES")
    console.print(f"ID: {definition.id}")
    console.print(f"Risk: {definition.risk_class.value}")
    console.print(f"Strategy: {definition.execution_strategy.value}")
    if runtime_output is not None:
        dump_yaml(definition.to_runtime_test(), runtime_output)
        console.print(f"Runtime definition written to: {runtime_output}")
    console.print("Network execution: NOT PERFORMED")


@app.command("build-security-graph")
def build_security_graph_command(
    registry_path: Annotated[Path, typer.Argument(help="Target registry YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write security graph YAML")],
) -> None:
    """Build a provenance graph from known targets and evidence relationships."""
    registry = load_model(registry_path, TargetRegistry)
    graph = build_security_graph(registry)
    dump_yaml(graph, output)
    console.print(f"Graph nodes: {len(graph.nodes)}")
    console.print(f"Graph edges: {len(graph.edges)}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("build-hypotheses")
def build_hypotheses_command(
    graph_path: Annotated[Path, typer.Argument(help="Security graph YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write hypothesis graph YAML")],
) -> None:
    """Create conservative observation hypotheses from the security graph."""
    from astp.security_graph import SecurityGraph

    graph = load_model(graph_path, SecurityGraph)
    hypotheses = build_observation_hypotheses(graph)
    dump_yaml(hypotheses, output)
    console.print(f"Hypotheses: {len(hypotheses.hypotheses)}")
    console.print("Hypotheses do not grant authorization or execution rights.")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("correlate-findings")
def correlate_findings_command(
    candidates_path: Annotated[Path, typer.Argument(help="YAML list of finding candidates")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write correlated findings YAML")],
) -> None:
    """Deduplicate evidence-backed finding candidates without increasing proof state."""
    raw = load_yaml(candidates_path)
    rows = raw.get("candidates")
    if not isinstance(rows, list):
        raise typer.BadParameter("finding candidate YAML must contain a 'candidates' list")
    candidates = [FindingCandidate.model_validate(item) for item in rows]
    findings = correlate_findings(candidates)
    dump_yaml(findings, output)
    console.print(f"Input candidates: {len(candidates)}")
    console.print(f"Correlated findings: {len(findings.findings)}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("render-report")
def render_report_command(
    findings_path: Annotated[Path, typer.Argument(help="Correlated findings YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write Markdown report")],
) -> None:
    """Render an evidence-oriented Markdown report and permit-gated retest checklist."""
    findings = load_model(findings_path, FindingSet)
    engagement = load_model(engagement_path, Engagement)
    rendered = render_markdown_report(engagement, findings)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    console.print(f"Findings: {len(findings.findings)}")
    console.print(f"Report written to: {output}")
    console.print("Retest entries are plans only; each execution still requires a fresh permit.")


@app.command("broker-permit")
def broker_permit_command(
    queue_path: Annotated[Path, typer.Argument(help="Work queue YAML")],
    queue_id: Annotated[str, typer.Option("--queue-id", help="Queue item ID")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Current test definition YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write signed permit YAML")],
    program_status_attestation: Annotated[
        Path | None,
        typer.Option("--program-status-attestation", help="Fresh program-status attestation YAML"),
    ] = None,
    semantic_clear: Annotated[
        list[str] | None,
        typer.Option("--semantic-clear", help="Semantic exclusion reviewed clear; repeatable"),
    ] = None,
    requested_rps: Annotated[float | None, typer.Option("--rps", help="Requested rate")] = None,
    ttl_seconds: Annotated[int, typer.Option("--ttl-seconds", help="Permit lifetime")] = 120,
) -> None:
    """Re-authorize one queued action and issue one permit; never execute it."""
    from astp.work_queue import WorkQueue

    queue = load_model(queue_path, WorkQueue)
    item = next((row for row in queue.items if row.queue_id == queue_id), None)
    if item is None:
        raise typer.BadParameter(f"unknown queue item: {queue_id}")
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    attestation = (
        load_model(program_status_attestation, ProgramOperationalAttestation)
        if program_status_attestation is not None
        else None
    )
    active_key_id, keys = _permit_keyring()
    try:
        receipt = broker_queue_item_permit(
            item,
            engagement,
            test,
            keys[active_key_id],
            key_id=active_key_id,
            ttl_seconds=ttl_seconds,
            operational_attestation=attestation,
            semantic_exclusion_clears=set(semantic_clear or []),
            requested_rps=requested_rps,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    dump_yaml(receipt.permit, output)
    console.print("Permit broker: ISSUED")
    console.print(f"Queue item: {receipt.queue_id}")
    console.print(f"Permit ID: {receipt.permit.payload.permit_id}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("init-planner-state")
def init_planner_state_command(
    queue_path: Annotated[Path, typer.Argument(help="Work queue YAML")],
    state_db: Annotated[Path, typer.Option("--state-db", help="Planner state SQLite DB")] = Path(
        ".astp"
    )
    / "planner.db",
) -> None:
    """Initialize durable planner state from a work queue."""
    from astp.work_queue import WorkQueue

    queue = load_model(queue_path, WorkQueue)
    initialize_planner_state(state_db, queue)
    console.print(f"Planner state initialized: {len(queue.items)} item(s)")
    console.print(f"State DB: {state_db}")
    console.print("Network execution: NOT PERFORMED")


@app.command("planner-item-status")
def planner_item_status_command(
    queue_id: Annotated[str, typer.Argument(help="Queue item ID")],
    state_db: Annotated[Path, typer.Option("--state-db", help="Planner state SQLite DB")] = Path(
        ".astp"
    )
    / "planner.db",
) -> None:
    """Show durable planner state for one queue item."""
    try:
        entry = get_planner_state(state_db, queue_id)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"{entry.queue_id}: {entry.state.value.upper()}")
    console.print(f"Attempts: {entry.attempts}")
    console.print(f"Permit ID: {entry.permit_id or 'none'}")
    console.print(f"Evidence ID: {entry.evidence_id or 'none'}")


@app.command("interpret-observation")
def interpret_observation_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write interpretation YAML")],
) -> None:
    """Interpret stored evidence into conservative signals; no requests are made."""
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    result = interpret_observation(evidence)
    dump_yaml(result, output)
    console.print(f"Signals: {len(result.signals)}")
    console.print(f"Surface expansion suggested: {'YES' if result.should_expand_surface else 'NO'}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("map-surface")
def map_surface_command(
    registry_path: Annotated[Path, typer.Argument(help="Target registry YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write surface map YAML")],
    max_endpoints: Annotated[int, typer.Option("--max-endpoints", help="Hard endpoint cap")] = 250,
) -> None:
    """Build a bounded route map from already-discovered targets."""
    registry = load_model(registry_path, TargetRegistry)
    try:
        result = build_surface_map(registry, max_endpoints=max_endpoints)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    dump_yaml(result, output)
    console.print(f"Surface endpoints: {len(result.endpoints)}")
    console.print(f"Truncated: {'YES' if result.truncated else 'NO'}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("show-adapters")
def show_adapters_command() -> None:
    """Display registered execution adapters and their safety contracts."""
    registry = builtin_adapter_registry()
    table = Table(title="ASTP Adapter Registry")
    table.add_column("Adapter")
    table.add_column("Network")
    table.add_column("Permit required")
    table.add_column("State changing")
    for adapter in registry.adapters:
        table.add_row(
            adapter.id,
            "YES" if adapter.network_capable else "NO",
            "YES" if adapter.requires_execution_permit else "NO",
            "YES" if adapter.state_changing else "NO",
        )
    console.print(table)


@app.command("check-adapter")
def check_adapter_command(
    dsl_path: Annotated[Path, typer.Argument(help="Security Test DSL YAML")],
    adapter_id: Annotated[
        str, typer.Option("--adapter", help="Adapter ID")
    ] = "http.observation.v1",
) -> None:
    """Validate DSL-to-adapter compatibility without execution."""
    definition = load_model(dsl_path, SecurityTestDefinition)
    registry = builtin_adapter_registry()
    try:
        ensure_adapter_compatible(registry.get(adapter_id), definition)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print("Adapter compatible: YES")
    console.print("Network execution: NOT PERFORMED")


@app.command("prepare-autonomy-session")
def prepare_autonomy_session_command(
    queue_path: Annotated[Path, typer.Argument(help="Work queue YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write session plan YAML")],
    max_actions: Annotated[int, typer.Option("--max-actions", help="Action budget")] = 20,
    max_requests: Annotated[int, typer.Option("--max-requests", help="Request budget")] = 20,
    max_errors: Annotated[int, typer.Option("--max-errors", help="Error budget")] = 3,
    max_seconds: Annotated[int, typer.Option("--max-seconds", help="Wall-clock budget")] = 900,
    max_depth: Annotated[int, typer.Option("--max-depth", help="Discovery depth budget")] = 3,
) -> None:
    """Prepare a bounded autonomy session plan; execution remains disabled."""
    from astp.work_queue import WorkQueue

    queue = load_model(queue_path, WorkQueue)
    budget = SessionBudget(
        max_actions=max_actions,
        max_requests=max_requests,
        max_errors=max_errors,
        max_wall_clock_seconds=max_seconds,
        max_discovery_depth=max_depth,
    )
    plan = prepare_autonomy_session(queue, budget)
    dump_yaml(plan, output)
    console.print(f"Prepared items: {len(plan.items)}")
    console.print(f"Budget allows session: {'YES' if plan.budget_decision.allowed else 'NO'}")
    console.print("Execution enabled: NO")
    console.print("Every network action still requires a fresh permit.")
    console.print(f"Written to: {output}")


@app.command("prioritize-targets")
def prioritize_targets_command(
    registry_path: Annotated[Path, typer.Argument(help="Target registry YAML")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Optional YAML output")
    ] = None,
) -> None:
    """Rank already-discovered targets using deterministic non-exploit heuristics."""
    registry = load_model(registry_path, TargetRegistry)
    rows = prioritize_registry(registry)
    table = Table(title="ASTP Surface Priorities")
    table.add_column("Score", justify="right")
    table.add_column("Target")
    for row in rows:
        table.add_row(str(row.score), row.target)
    console.print(table)
    if output is not None:
        dump_yaml({"targets": [row.model_dump(mode="json") for row in rows]}, output)
        console.print(f"Written to: {output}")
    console.print("Network execution: NOT PERFORMED")


@app.command("analyze-web-posture")
def analyze_web_posture_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write posture assessment YAML")],
) -> None:
    """Analyze already-collected HTTP headers; signals are not confirmed vulnerabilities."""
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    result = analyze_http_posture(evidence)
    dump_yaml(result, output)
    console.print(f"Signals: {len(result.signals)}")
    console.print("Confirmed vulnerabilities: 0")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("init-session-ledger")
def init_session_ledger_command(
    session_id: Annotated[str, typer.Argument(help="Session identifier")],
    ledger_db: Annotated[
        Path, typer.Option("--ledger-db", help="Durable autonomy session ledger")
    ] = Path(".astp")
    / "session-ledger.db",
) -> None:
    """Initialize an atomic session budget ledger; no network action is performed."""
    counters = initialize_session_ledger(ledger_db, session_id)
    console.print(f"Session ledger initialized: {counters.session_id}")
    console.print(f"Actions reserved: {counters.actions_reserved}")
    console.print(f"Requests reserved: {counters.requests_reserved}")
    console.print("Network execution: NOT PERFORMED")


@app.command("session-ledger-status")
def session_ledger_status_command(
    session_id: Annotated[str, typer.Argument(help="Session identifier")],
    ledger_db: Annotated[
        Path, typer.Option("--ledger-db", help="Durable autonomy session ledger")
    ] = Path(".astp")
    / "session-ledger.db",
) -> None:
    """Show durable autonomy counters."""
    try:
        counters = get_session_counters(ledger_db, session_id)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    console.print(f"Session: {counters.session_id}")
    console.print(f"Actions reserved: {counters.actions_reserved}")
    console.print(f"Requests reserved: {counters.requests_reserved}")
    console.print(f"Completed: {counters.completed}")
    console.print(f"Errors: {counters.errors}")


@app.command("snapshot-policy")
def snapshot_policy_command(
    engagement_path: Annotated[Path, typer.Argument(help="Engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Test definition YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Policy snapshot YAML")],
) -> None:
    """Capture a policy digest for later drift detection."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    snapshot = capture_policy_snapshot(engagement, test)
    dump_yaml(snapshot, output)
    console.print(f"Policy snapshot: {snapshot.digest}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("build-frontier")
def build_frontier_command(
    registry_path: Annotated[Path, typer.Argument(help="Target registry YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Crawl frontier YAML")],
    max_depth: Annotated[int, typer.Option("--max-depth", help="Maximum discovery depth")] = 3,
) -> None:
    """Build a bounded crawl frontier from discovered targets without requesting them."""
    registry = load_model(registry_path, TargetRegistry)
    try:
        frontier = build_frontier(registry, max_depth=max_depth)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    dump_yaml(frontier, output)
    console.print(f"Frontier items: {len(frontier.items)}")
    console.print(f"Maximum depth: {frontier.max_depth}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("choose-observation-method")
def choose_observation_method_command(
    body_required: Annotated[
        bool, typer.Option("--body-required", help="Require response body evidence")
    ] = False,
) -> None:
    """Choose HEAD-first or GET when body evidence is explicitly required."""
    choice = choose_observation_method(body_required=body_required)
    console.print(f"Method: {choice.method}")
    console.print(f"Reason: {choice.reason.value}")
    console.print("Network execution: NOT PERFORMED")


@app.command("feedback-evidence")
def feedback_evidence_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    engagement_path: Annotated[Path, typer.Argument(help="Engagement YAML")],
    registry_path: Annotated[Path, typer.Argument(help="Target registry YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Updated registry YAML")],
    include_links: Annotated[bool, typer.Option("--links/--no-links")] = True,
    max_candidates: Annotated[int, typer.Option("--max-candidates")] = 50,
) -> None:
    """Feed stored evidence back into the target registry; no network action is performed."""
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    engagement = load_model(engagement_path, Engagement)
    registry = load_model(registry_path, TargetRegistry)
    result = apply_evidence_feedback(
        evidence,
        engagement,
        registry,
        include_links=include_links,
        max_candidates=max_candidates,
    )
    dump_yaml(result.registry, output)
    console.print(f"Candidates: {len(result.discovered.candidates)}")
    console.print(f"Registry entries added: {result.added_entries}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("verify-execution-trace")
def verify_execution_trace_command(
    trace_path: Annotated[Path, typer.Argument(help="Hash-linked execution trace JSONL")],
) -> None:
    """Verify the hash-linked autonomous execution trace."""
    try:
        valid = verify_execution_trace(trace_path)
    except (OSError, ValueError) as exc:
        console.print(f"Execution trace valid: NO\n{exc}")
        raise typer.Exit(code=9) from exc
    console.print(f"Execution trace valid: {'YES' if valid else 'NO'}")
    if not valid:
        raise typer.Exit(code=9)


@app.command("run-observation-session")
def run_observation_session_command(
    queue_path: Annotated[Path, typer.Argument(help="Authorizable work queue YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Observation test YAML")],
    attestation_path: Annotated[
        Path, typer.Option("--program-status-attestation", help="Fresh program status attestation")
    ],
    execute: Annotated[
        bool, typer.Option("--execute", help="Explicitly enable bounded GET/HEAD execution")
    ] = False,
    semantic_clear: Annotated[
        list[str] | None,
        typer.Option("--semantic-clear", help="Reviewed semantic exclusion clear; repeatable"),
    ] = None,
    requested_rps: Annotated[float | None, typer.Option("--rps")] = None,
    max_actions: Annotated[int, typer.Option("--max-actions")] = 3,
    max_requests: Annotated[int, typer.Option("--max-requests")] = 3,
    max_errors: Annotated[int, typer.Option("--max-errors")] = 1,
    max_actions_per_origin: Annotated[int, typer.Option("--max-actions-per-origin")] = 3,
    ttl_seconds: Annotated[int, typer.Option("--ttl-seconds")] = 120,
    session_id: Annotated[str, typer.Option("--session-id")] = "observation-session",
    ledger_db: Annotated[Path, typer.Option("--ledger-db")] = Path(".astp") / "session-ledger.db",
    trace_path: Annotated[Path, typer.Option("--trace")] = Path(".astp") / "execution-trace.jsonl",
    evidence_dir: Annotated[Path, typer.Option("--evidence-dir")] = Path(".astp") / "evidence",
    manifest_path: Annotated[Path, typer.Option("--manifest")] = Path(".astp")
    / "evidence-manifest.jsonl",
    audit_path: Annotated[Path, typer.Option("--audit")] = DEFAULT_AUDIT_PATH,
    runtime_db_path: Annotated[Path, typer.Option("--runtime-db")] = DEFAULT_RUNTIME_DB_PATH,
    rate_state_path: Annotated[Path, typer.Option("--rate-state")] = Path(".astp")
    / "rate-state.json",
    timeout_seconds: Annotated[float, typer.Option("--timeout")] = DEFAULT_TIMEOUT_SECONDS,
    max_body_bytes: Annotated[int, typer.Option("--max-body-bytes")] = DEFAULT_MAX_BODY_BYTES,
) -> None:
    """Run a bounded sequential observation session with one fresh permit per request."""
    if not execute:
        raise typer.BadParameter(
            "execution is disabled by default; pass --execute only for an authorized engagement"
        )
    queue = load_model(queue_path, WorkQueue)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    attestation = load_model(attestation_path, ProgramOperationalAttestation)
    active_key_id, keys = _permit_keyring()
    signing_key = keys[active_key_id]
    snapshot = capture_policy_snapshot(engagement, test)
    initialize_session_ledger(ledger_db, session_id)
    append_trace_event(trace_path, "session.started", message=session_id)

    def executor(item):
        receipt = broker_queue_item_permit(
            item,
            engagement,
            test,
            signing_key,
            key_id=active_key_id,
            ttl_seconds=ttl_seconds,
            operational_attestation=attestation,
            semantic_exclusion_clears=set(semantic_clear or []),
            requested_rps=requested_rps,
        )
        append_trace_event(
            trace_path,
            "permit.issued",
            queue_id=item.queue_id,
            permit_id=receipt.permit.payload.permit_id,
        )
        evidence_path = evidence_dir / f"{session_id}-{item.queue_id}.json"
        result = observe_http(
            receipt.permit,
            engagement,
            test,
            keys,
            target=item.target,
            method=item.method,
            identity=None,
            requested_rps=requested_rps,
            state_path=DEFAULT_STATE_PATH,
            audit_path=audit_path,
            evidence_path=evidence_path,
            manifest_path=manifest_path,
            rate_state_path=rate_state_path,
            runtime_db_path=runtime_db_path,
            timeout_seconds=timeout_seconds,
            max_body_bytes=max_body_bytes,
        )
        append_trace_event(
            trace_path,
            "evidence.recorded",
            queue_id=item.queue_id,
            permit_id=receipt.permit.payload.permit_id,
            evidence_id=result.evidence.evidence_id,
        )
        return receipt.permit.payload.permit_id, result.evidence.evidence_id

    result = run_controlled_queue(
        queue,
        engagement,
        test,
        attestation,
        snapshot,
        ledger_db,
        session_id,
        executor,
        max_actions=max_actions,
        max_requests=max_requests,
        max_errors=max_errors,
        max_actions_per_origin=max_actions_per_origin,
        breaker=FailureCircuitBreaker(max_consecutive_failures=max(1, max_errors)),
    )
    append_trace_event(trace_path, "session.finished", message=result.stop_reason)
    console.print(f"Session: {result.session_id}")
    console.print(f"Completed actions: {sum(1 for row in result.outcomes if row.completed)}")
    console.print(f"Failed actions: {sum(1 for row in result.outcomes if not row.completed)}")
    console.print(f"Stop reason: {result.stop_reason or 'queue exhausted'}")
    console.print("Network execution: bounded permit-gated GET/HEAD")
    console.print(f"Execution trace: {trace_path}")


@app.command("session-report")
def session_report_command(
    session_id: Annotated[str, typer.Argument(help="Session identifier")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Session summary YAML")],
    ledger_db: Annotated[
        Path, typer.Option("--ledger-db", help="Durable autonomy session ledger")
    ] = Path(".astp")
    / "session-ledger.db",
    trace_path: Annotated[Path, typer.Option("--trace", help="Hash-linked execution trace")] = Path(
        ".astp"
    )
    / "execution-trace.jsonl",
) -> None:
    """Summarize durable session counters and trace events without network access."""
    try:
        counters = get_session_counters(ledger_db, session_id)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    summary = summarize_session_execution(counters, trace_path)
    dump_yaml(summary, output)
    console.print(f"Completed: {summary.completed}")
    console.print(f"Errors: {summary.errors}")
    console.print(f"Permits issued: {summary.permits_issued}")
    console.print(f"Evidence records: {summary.evidence_records}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("resume-session-check")
def resume_session_check_command(
    queue_path: Annotated[Path, typer.Argument(help="Work queue YAML")],
    state_db: Annotated[
        Path, typer.Option("--state-db", help="Durable planner state SQLite database")
    ] = Path(".astp")
    / "planner.db",
) -> None:
    """Determine which queue items may be safely re-planned after interruption."""
    queue = load_model(queue_path, WorkQueue)
    entries = []
    for item in queue.items:
        try:
            entries.append(get_planner_state(state_db, item.queue_id))
        except ValueError:
            continue
    result = evaluate_resume(entries)
    console.print(f"Resume allowed: {'YES' if result.allowed else 'NO'}")
    console.print(f"Resumable: {', '.join(result.resumable_queue_ids) or 'none'}")
    console.print(f"Blocked: {', '.join(result.blocked_queue_ids) or 'none'}")
    console.print(result.reason)
    console.print("Network execution: NOT PERFORMED")


@app.command("fingerprint-http")
def fingerprint_http_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write fingerprint YAML")],
) -> None:
    """Build an evidence-backed HTTP technology fingerprint without network access."""
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    result = fingerprint_http(evidence)
    dump_yaml(result, output)
    console.print(f"Fingerprint observations: {len(result.observations)}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("analyze-protocol")
def analyze_protocol_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write analyzer result YAML")],
) -> None:
    """Analyze headers, cookies, CORS, and HTTPS posture from stored evidence only."""
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    result = analyze_protocol_posture(evidence)
    dump_yaml(result, output)
    console.print(f"Analyzer signals: {len(result.signals)}")
    console.print("Confirmed vulnerabilities: 0")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("assess")
def assess_command(
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Observation test YAML")],
    registry_path: Annotated[Path, typer.Argument(help="Target registry YAML")],
    evidence_dir: Annotated[
        Path, typer.Option("--evidence-dir", help="Stored HTTP evidence directory")
    ],
    report_path: Annotated[
        Path, typer.Option("--output", "-o", help="Write Markdown assessment report")
    ],
    result_path: Annotated[
        Path | None, typer.Option("--result", help="Optional structured assessment YAML")
    ] = None,
    session_id: Annotated[str, typer.Option("--session-id")] = "assessment",
    program_status_attestation: Annotated[
        Path | None,
        typer.Option("--program-status-attestation", help="Optional status context for replanning"),
    ] = None,
    semantic_clear: Annotated[
        list[str] | None,
        typer.Option("--semantic-clear", help="Reviewed semantic exclusion clear; repeatable"),
    ] = None,
    requested_rps: Annotated[float | None, typer.Option("--rps")] = None,
) -> None:
    """Run the offline fingerprint-to-report assessment pipeline on stored evidence."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    registry = load_model(registry_path, TargetRegistry)
    attestation = (
        load_model(program_status_attestation, ProgramOperationalAttestation)
        if program_status_attestation is not None
        else None
    )
    evidence_rows = load_evidence_directory(evidence_dir)
    excluded_terms = set(engagement.program.excluded_finding_types) if engagement.program else set()
    result = assess_evidence(
        session_id,
        evidence_rows,
        registry,
        engagement,
        test,
        operational_attestation=attestation,
        semantic_exclusion_clears=set(semantic_clear or []),
        requested_rps=requested_rps,
        excluded_finding_terms=excluded_terms,
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(result.report_markdown, encoding="utf-8")
    if result_path is not None:
        dump_yaml(result, result_path)
    console.print(f"Evidence processed: {len(evidence_rows)}")
    console.print(f"Invalid evidence excluded: {len(result.invalid_evidence_ids)}")
    console.print(
        f"Fingerprint observations: {sum(len(x.observations) for x in result.fingerprints)}"
    )
    console.print(f"Normalized signals: {len(result.signals)}")
    console.print(f"Finding candidates: {len(result.candidates.candidates)}")
    console.print(f"Correlated findings: {len(result.findings.findings)}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Report: {report_path}")


@app.command("persist-findings")
def persist_findings_command(
    findings_path: Annotated[Path, typer.Argument(help="FindingSet YAML")],
    repository_db: Annotated[
        Path, typer.Option("--repository-db", help="Finding repository SQLite")
    ],
    request_retest: Annotated[
        bool, typer.Option("--request-retest", help="Mark stored findings for explicit retest")
    ] = False,
) -> None:
    """Persist finding state and optional retest intent without executing a retest."""
    findings = load_model(findings_path, FindingSet)
    for finding in findings.findings:
        upsert_finding(repository_db, finding)
        if request_retest:
            set_retest_state(repository_db, finding.id, required=True)
    console.print(f"Findings persisted: {len(findings.findings)}")
    console.print(f"Retest requested: {'YES' if request_retest else 'NO'}")
    console.print("Network execution: NOT PERFORMED")


@app.command("validate-assessment-recovery")
def validate_assessment_recovery_command(
    result_path: Annotated[Path, typer.Argument(help="Structured AssessmentResult YAML")],
) -> None:
    """Validate offline field/recovery invariants for a completed assessment result."""
    from astp.assessment import AssessmentResult

    result = load_model(result_path, AssessmentResult)
    validation = validate_assessment_recovery(result)
    for check in validation.checks:
        console.print(f"{check.name}: {'PASS' if check.passed else 'FAIL'} — {check.detail}")
    console.print(f"Overall: {'PASS' if validation.passed else 'FAIL'}")
    console.print("Network execution: NOT PERFORMED")
    if not validation.passed:
        raise typer.Exit(code=10)


@app.command("inventory-javascript")
def inventory_javascript_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write JS inventory YAML")],
) -> None:
    """Inventory script references from stored HTML evidence only."""
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    result = inventory_javascript(evidence)
    dump_yaml(result, output)
    console.print(f"JavaScript artifacts: {len(result.artifacts)}")
    console.print("Network execution: NOT PERFORMED")


@app.command("show-network-capabilities")
def show_network_capabilities_command() -> None:
    """Show permit-gated DNS/TLS worker contracts without executing them."""
    table = Table(title="ASTP Network Capability Contracts")
    table.add_column("Capability")
    table.add_column("Permit")
    table.add_column("State changing")
    table.add_column("Arbitrary network")
    for capability in builtin_network_capabilities():
        table.add_row(
            capability.id.value,
            "YES" if capability.requires_execution_permit else "NO",
            "YES" if capability.state_changing else "NO",
            "YES" if capability.arbitrary_network else "NO",
        )
    console.print(table)
    console.print("Network execution: NOT PERFORMED")


@app.command("fuse-confidence")
def fuse_confidence_command(
    result_path: Annotated[Path, typer.Argument(help="Structured AssessmentResult YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write confidence fusion YAML")],
) -> None:
    """Fuse repeated normalized signals without upgrading proof state."""
    from astp.assessment import AssessmentResult

    result = load_model(result_path, AssessmentResult)
    fused = fuse_normalized_signals(result.signals)
    dump_yaml(
        {"schema_version": "1", "items": [item.model_dump(mode="json") for item in fused]},
        output,
    )
    console.print(f"Fused signal groups: {len(fused)}")
    console.print("Proof states changed: 0")
    console.print("Network execution: NOT PERFORMED")


@app.command("build-assessment-lineage")
def build_assessment_lineage_command(
    result_path: Annotated[Path, typer.Argument(help="Structured AssessmentResult YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write lineage YAML")],
) -> None:
    """Build evidence-to-signal-to-finding lineage from a stored assessment."""
    from astp.assessment import AssessmentResult

    result = load_model(result_path, AssessmentResult)
    lineage = build_assessment_lineage(result)
    dump_yaml(lineage, output)
    console.print(f"Lineage nodes: {len(lineage.nodes)}")
    console.print(f"Lineage edges: {len(lineage.edges)}")
    console.print("Network execution: NOT PERFORMED")


@app.command("score-assessment-risk")
def score_assessment_risk_command(
    result_path: Annotated[Path, typer.Argument(help="Structured AssessmentResult YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write contextual risk YAML")],
    exposure: Annotated[Exposure, typer.Option("--exposure")] = Exposure.UNKNOWN,
    asset_importance: Annotated[
        AssetImportance,
        typer.Option("--asset-importance"),
    ] = AssetImportance.UNKNOWN,
) -> None:
    """Calculate non-CVSS contextual ranking inputs for correlated findings."""
    from astp.assessment import AssessmentResult

    result = load_model(result_path, AssessmentResult)
    context = RiskContext(exposure=exposure, asset_importance=asset_importance)
    rows = [
        {
            "finding_id": finding.id,
            "risk": score_finding_context(finding, context).model_dump(mode="json"),
        }
        for finding in result.findings.findings
    ]
    dump_yaml({"schema_version": "1", "is_cvss": False, "findings": rows}, output)
    console.print(f"Contextual risk rows: {len(rows)}")
    console.print("CVSS calculated: NO")
    console.print("Network execution: NOT PERFORMED")


@app.command("build-assessment-manifest")
def build_assessment_manifest_command(
    result_path: Annotated[Path, typer.Argument(help="Structured AssessmentResult YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write manifest YAML")],
) -> None:
    """Build an integrity-bound manifest for a stored assessment."""
    from astp.assessment import AssessmentResult

    result = load_model(result_path, AssessmentResult)
    manifest = build_assessment_manifest(result)
    dump_yaml(manifest, output)
    console.print(f"Manifest hash: {manifest.manifest_hash}")
    console.print("Network execution: NOT PERFORMED")


@app.command("verify-assessment-manifest")
def verify_assessment_manifest_command(
    manifest_path: Annotated[Path, typer.Argument(help="Assessment manifest YAML")],
) -> None:
    """Verify assessment manifest integrity."""
    manifest = load_model(manifest_path, AssessmentManifest)
    valid = verify_assessment_manifest(manifest)
    console.print(f"Assessment manifest valid: {'YES' if valid else 'NO'}")
    console.print("Network execution: NOT PERFORMED")
    if not valid:
        raise typer.Exit(code=11)


@app.command("review-assessment")
def review_assessment_command(
    manifest_path: Annotated[Path, typer.Argument(help="Assessment manifest YAML")],
    reviewer: Annotated[str, typer.Option("--reviewer")],
    decision: Annotated[ReviewDecision, typer.Option("--decision")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write operator review YAML")],
    note: Annotated[list[str] | None, typer.Option("--note")] = None,
) -> None:
    """Record explicit human review bound to an integrity-verified assessment."""
    manifest = load_model(manifest_path, AssessmentManifest)
    review = record_operator_review(manifest, reviewer, decision, notes=note or [])
    dump_yaml(review, output)
    console.print(f"Decision: {review.decision.value.upper()}")
    console.print("Network execution: NOT PERFORMED")


@app.command("build-review-package")
def build_review_package_command(
    result_path: Annotated[Path, typer.Argument(help="Structured AssessmentResult YAML")],
    output_dir: Annotated[Path, typer.Option("--output-dir", help="Review package directory")],
) -> None:
    """Assemble report, structured result, manifest, and lineage for operator review."""
    from astp.assessment import AssessmentResult

    result = load_model(result_path, AssessmentResult)
    package = build_review_package(result, output_dir)
    console.print(f"Manifest hash: {package.manifest.manifest_hash}")
    console.print(f"Lineage nodes: {len(package.lineage.nodes)}")
    console.print("Network execution: NOT PERFORMED")


@app.command("export-portable-assessment")
def export_portable_assessment_command(
    manifest_path: Annotated[Path, typer.Argument(help="Assessment manifest YAML")],
    review_path: Annotated[Path, typer.Argument(help="Operator review YAML")],
    report_path: Annotated[Path, typer.Argument(help="Assessment Markdown report")],
    result_path: Annotated[Path, typer.Argument(help="Structured assessment YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Portable ZIP")],
) -> None:
    """Export a reviewed assessment as an integrity-checkable portable archive."""
    from astp.operator_review import OperatorReview

    manifest = load_model(manifest_path, AssessmentManifest)
    review = load_model(review_path, OperatorReview)
    index = export_portable_assessment(
        output,
        manifest=manifest,
        review=review,
        report_path=report_path,
        result_path=result_path,
    )
    console.print(f"Portable entries: {len(index.entries)}")
    console.print(f"Archive valid: {'YES' if verify_portable_assessment(output) else 'NO'}")
    console.print("Network execution: NOT PERFORMED")


@app.command("derive-network-evidence")
def derive_network_evidence_command(
    evidence_path: Annotated[Path, typer.Argument(help="HTTP observation evidence JSON")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write derived evidence YAML")],
) -> None:
    """Derive DNS/TLS provenance from stored HTTP transport evidence; no network."""
    evidence = HttpObservationEvidence.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    dns, tls = derive_network_capability_evidence(evidence)
    dump_yaml(
        {
            "schema_version": "1",
            "dns": dns.model_dump(mode="json") if dns else None,
            "tls": tls.model_dump(mode="json") if tls else None,
        },
        output,
    )
    console.print(f"DNS provenance: {'YES' if dns else 'NO'}")
    console.print(f"TLS provenance: {'YES' if tls else 'NO'}")
    console.print("Network execution: NOT PERFORMED")


@app.command("analyze-javascript-static")
def analyze_javascript_static_command(
    artifact_path: Annotated[Path, typer.Argument(help="Stored JavaScript artifact")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write analysis YAML")],
) -> None:
    """Analyze a locally stored JavaScript artifact without fetching it."""
    result = analyze_javascript_file(artifact_path)
    dump_yaml(result, output)
    console.print(f"Static JavaScript signals: {len(result.signals)}")
    console.print("Network execution: NOT PERFORMED")


@app.command("plan-javascript-fetches")
def plan_javascript_fetches_command(
    inventory_path: Annotated[Path, typer.Argument(help="JavaScriptInventory YAML")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Write fetch plan YAML")],
) -> None:
    """Convert discovered JavaScript URLs into permit-required retrieval candidates."""
    from astp.javascript_inventory import JavaScriptInventory

    inventory = load_model(inventory_path, JavaScriptInventory)
    plan = plan_javascript_artifacts(inventory)
    dump_yaml(plan, output)
    console.print(f"Artifact candidates: {len(plan.items)}")
    console.print("Network execution: NOT PERFORMED")


@app.command("review-verification")
def review_verification_command(
    queue_db: Annotated[Path, typer.Argument(help="Verification queue SQLite database")],
    queue_id: Annotated[str, typer.Option("--queue-id")],
    reviewer: Annotated[str, typer.Option("--reviewer")],
    decision: Annotated[VerificationReviewDecision, typer.Option("--decision")],
    output: Annotated[Path, typer.Option("--output", "-o")],
) -> None:
    """Review a durable verification item without authorizing or executing it."""
    items = {item.id: item for item in list_verification_queue(queue_db)}
    if queue_id not in items:
        raise typer.BadParameter("verification queue item not found")
    review = review_verification_item(items[queue_id], reviewer, decision)
    dump_yaml(review, output)
    console.print(f"Verification review: {review.decision.value.upper()}")
    console.print("Network execution: NOT PERFORMED")


@app.command("broker-verification")
def broker_verification_command(
    queue_db: Annotated[Path, typer.Argument(help="Verification queue SQLite database")],
    review_path: Annotated[Path, typer.Argument(help="VerificationReview YAML")],
    queue_id: Annotated[str, typer.Option("--queue-id")],
    output: Annotated[Path, typer.Option("--output", "-o")],
) -> None:
    """Turn an approved review into a policy-authorization candidate only."""
    items = {item.id: item for item in list_verification_queue(queue_db)}
    if queue_id not in items:
        raise typer.BadParameter("verification queue item not found")
    review = load_model(review_path, VerificationReview)
    candidate = broker_reviewed_verification(items[queue_id], review)
    dump_yaml(candidate, output)
    console.print("Policy authorization still required: YES")
    console.print("Fresh permit still required: YES")
    console.print("Network execution: NOT PERFORMED")


@app.command("check-assessment-resume")
def check_assessment_resume_command(
    checkpoint_path: Annotated[Path, typer.Argument(help="Assessment checkpoint JSON/YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Current test definition YAML")],
) -> None:
    """Check checkpoint integrity and policy continuity before assessment resume."""
    from astp.assessment_checkpoint import AssessmentCheckpoint

    checkpoint = load_model(checkpoint_path, AssessmentCheckpoint)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    decision = evaluate_assessment_resume(
        checkpoint,
        engagement_id=engagement.id,
        current_policy_digest=policy_digest(engagement, test),
    )
    console.print(f"Resume allowed: {'YES' if decision.allowed else 'NO'}")
    console.print(f"Replan required: {'YES' if decision.requires_replan else 'NO'}")
    for reason in decision.reasons:
        console.print(f"- {reason}")
    console.print("Network execution: NOT PERFORMED")
    if not decision.allowed:
        raise typer.Exit(code=12)


@app.command("quarantine-evidence")
def quarantine_evidence_command(
    repository_db: Annotated[Path, typer.Argument(help="Evidence quarantine SQLite DB")],
    evidence_id: Annotated[str, typer.Option("--evidence-id")],
    reason: Annotated[str, typer.Option("--reason")],
) -> None:
    """Persist an integrity or policy quarantine decision for evidence."""
    item = quarantine_evidence(repository_db, evidence_id, reason)
    console.print(f"Quarantined evidence: {item.evidence_id}")
    console.print("Network execution: NOT PERFORMED")


@app.command("journal-session")
def journal_session_command(
    journal_path: Annotated[Path, typer.Argument(help="Hash-linked session journal JSONL")],
    session_id: Annotated[str, typer.Option("--session-id")],
    event: Annotated[str, typer.Option("--event")],
) -> None:
    """Append and verify a hash-linked assessment session event."""
    entry = append_session_event(journal_path, session_id, event)
    console.print(f"Journal sequence: {entry.sequence}")
    console.print(f"Journal valid: {'YES' if verify_session_journal(journal_path) else 'NO'}")
    console.print("Network execution: NOT PERFORMED")


@app.command("assessment-readiness")
def assessment_readiness_command(
    policy_ready: Annotated[bool, typer.Option("--policy-ready/--policy-blocked")] = False,
    attestation_fresh: Annotated[
        bool, typer.Option("--attestation-fresh/--attestation-stale")
    ] = False,
    permit_keys: Annotated[bool, typer.Option("--permit-keys/--no-permit-keys")] = False,
    evidence_store: Annotated[bool, typer.Option("--evidence-store/--no-evidence-store")] = False,
    worker_contracts: Annotated[
        bool, typer.Option("--worker-contracts/--no-worker-contracts")
    ] = False,
) -> None:
    """Evaluate deterministic prerequisites for a controlled assessment session."""
    result = evaluate_assessment_readiness(
        policy_ready=policy_ready,
        attestation_fresh=attestation_fresh,
        permit_keys_configured=permit_keys,
        evidence_store_ready=evidence_store,
        worker_contracts_ready=worker_contracts,
    )
    for check in result.checks:
        console.print(f"{check.name}: {'READY' if check.ready else 'BLOCKED'}")
    console.print(f"Overall ready: {'YES' if result.ready else 'NO'}")
    console.print("Network execution: NOT PERFORMED")


@app.command("finalize-report")
def finalize_report_command(
    manifest_path: Annotated[Path, typer.Argument(help="Assessment manifest YAML")],
    review_path: Annotated[Path, typer.Argument(help="Operator review YAML")],
    report_path: Annotated[Path, typer.Argument(help="Reviewed report Markdown")],
    output: Annotated[Path, typer.Option("--output", "-o")],
) -> None:
    """Finalize a report only when review and manifest integrity agree."""
    from astp.operator_review import OperatorReview

    manifest = load_model(manifest_path, AssessmentManifest)
    review = load_model(review_path, OperatorReview)
    finalization = finalize_report(manifest, review, report_path)
    dump_yaml(finalization, output)
    console.print(f"Publishable: {'YES' if finalization.publishable else 'NO'}")
    console.print("Network execution: NOT PERFORMED")


@app.command("build-publication-bundle")
def build_publication_bundle_command(
    finalization_path: Annotated[Path, typer.Argument(help="ReportFinalization YAML")],
    artifact: Annotated[
        list[Path], typer.Option("--artifact", help="Artifact to include; repeatable")
    ],
    output: Annotated[Path, typer.Option("--output", "-o", help="Publication ZIP")],
) -> None:
    """Build an integrity-checkable bundle after explicit assessment approval."""
    finalization = load_model(finalization_path, ReportFinalization)
    index = build_publication_bundle(output, finalization, artifact)
    console.print(f"Publication entries: {len(index.entries)}")
    console.print(f"Bundle valid: {'YES' if verify_publication_bundle(output) else 'NO'}")
    console.print("Network execution: NOT PERFORMED")


@app.command("closure-gate")
def closure_gate_command(
    review_path: Annotated[Path, typer.Argument(help="OperatorReview YAML")],
    finalization_path: Annotated[Path, typer.Argument(help="ReportFinalization YAML")],
    unresolved_verifications: Annotated[int, typer.Option("--unresolved-verifications")] = 0,
    quarantined_evidence: Annotated[int, typer.Option("--quarantined-evidence")] = 0,
) -> None:
    """Require approved finalization and cleared queues before assessment closure."""
    from astp.operator_review import OperatorReview

    review = load_model(review_path, OperatorReview)
    finalization = load_model(finalization_path, ReportFinalization)
    decision = evaluate_closure(
        review,
        finalization,
        unresolved_verifications=unresolved_verifications,
        quarantined_evidence=quarantined_evidence,
    )
    console.print(f"Assessment closable: {'YES' if decision.closable else 'NO'}")
    for reason in decision.reasons:
        console.print(f"- {reason}")
    console.print("Network execution: NOT PERFORMED")
    if not decision.closable:
        raise typer.Exit(code=13)


@app.command("evaluate-test")
def evaluate_test_command(
    engagement_path: Annotated[
        Path,
        typer.Argument(help="Engagement YAML"),
    ],
    test_path: Annotated[
        Path,
        typer.Argument(help="Test definition YAML"),
    ],
    target: Annotated[
        str,
        typer.Option("--target", help="Target URL/host"),
    ],
    context: Annotated[
        list[str] | None,
        typer.Option(
            "--context",
            help="Available context item; repeatable",
        ),
    ] = None,
    approved: Annotated[
        bool,
        typer.Option(
            "--approved",
            help="Record explicit approval",
        ),
    ] = False,
) -> None:
    """Evaluate whether a test would be allowed. It does not execute the test."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)

    request = EvaluationRequest(
        target=target,
        available_context=set(context or []),
        approved=approved,
    )

    result = evaluate_test(
        engagement,
        test,
        request,
    )

    table = Table(title="ASTP Policy Decision")
    table.add_column("Field")
    table.add_column("Value")

    table.add_row("Test", f"{test.id} — {test.title}")
    table.add_row("Target", target)
    table.add_row(
        "In scope",
        "YES" if result.target_in_scope else "NO",
    )
    table.add_row("Risk", test.risk_class.value)
    table.add_row("Decision", result.decision.value.upper())
    table.add_row("Execution", "NOT PERFORMED (policy evaluation only)")
    table.add_row(
        "Missing context",
        ", ".join(result.missing_context) or "none",
    )

    console.print(table)

    for reason in result.reasons:
        console.print(f"- {reason}")


@app.command("prepare-capability-action")
def prepare_capability_action_command(
    capability_id: Annotated[str, typer.Option("--capability", help="Capability contract id")],
    operation: Annotated[
        CapabilityOperation, typer.Option("--operation", help="Exact bounded operation")
    ],
    target: Annotated[str, typer.Option("--target", help="Exact host or URL target")],
    output: Annotated[Path, typer.Option("--output", help="Write action YAML here")],
    port: Annotated[
        int | None, typer.Option("--port", help="Explicit network port when required")
    ] = None,
) -> None:
    """Prepare an exact capability action. No network execution occurs."""
    action = CapabilityAction(
        capability_id=capability_id,
        operation=operation,
        target=target,
        port=port,
    )
    dump_yaml(action, output)
    console.print(f"Action ID: {action.action_id()}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("issue-capability-grant")
def issue_capability_grant_command(
    permit_path: Annotated[Path, typer.Argument(help="Signed execution permit YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Current test definition YAML")],
    action_path: Annotated[Path, typer.Argument(help="Exact capability action YAML")],
    output: Annotated[
        Path, typer.Option("--output", help="Write signed capability grant YAML here")
    ],
) -> None:
    """Bind a verified execution permit to one exact capability action."""
    permit = load_model(permit_path, SignedExecutionPermit)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    action = load_model(action_path, CapabilityAction)
    _, keys = _permit_keyring()
    try:
        grant = issue_capability_grant(permit, action, engagement, test, keys)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    dump_yaml(grant, output)
    console.print(f"Capability grant: ISSUED for action {grant.payload.action_id}")
    console.print("Network execution: NOT PERFORMED")
    console.print(f"Written to: {output}")


@app.command("execute-capability")
def execute_capability_command(
    grant_path: Annotated[Path, typer.Argument(help="Signed capability grant YAML")],
    permit_path: Annotated[Path, typer.Argument(help="Signed execution permit YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Current test definition YAML")],
    action_path: Annotated[Path, typer.Argument(help="Exact capability action YAML")],
    output: Annotated[Path, typer.Option("--output", help="Write typed evidence JSON here")],
    manifest: Annotated[Path, typer.Option("--manifest", help="Evidence manifest JSONL")] = Path(
        ".astp"
    )
    / "evidence-manifest.jsonl",
    state: Annotated[
        Path, typer.Option("--state", help="Permit lifecycle state file")
    ] = DEFAULT_STATE_PATH,
    execute: Annotated[
        bool,
        typer.Option("--execute", help="Explicitly allow this one permit-gated network action"),
    ] = False,
) -> None:
    """Execute one bounded DNS/TLS action only with an exact signed grant."""
    if not execute:
        console.print("Execution blocked: pass --execute for this exact permit-gated action.")
        console.print("Network execution: NOT PERFORMED")
        raise typer.Exit(code=2)
    grant = load_model(grant_path, SignedCapabilityGrant)
    permit = load_model(permit_path, SignedExecutionPermit)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    action = load_model(action_path, CapabilityAction)
    _, keys = _permit_keyring()
    try:
        evidence = dispatch_capability_observation(
            grant,
            permit,
            action,
            engagement,
            test,
            keys,
            state_path=state,
            evidence_path=output,
            manifest_path=manifest,
        )
    except (ValueError, RuntimeError) as exc:
        console.print(f"Capability observation completed: [bold]NO[/bold]\n{exc}")
        raise typer.Exit(code=6) from exc
    console.print("Capability observation completed: YES")
    console.print(f"Evidence ID: {evidence.evidence_id}")
    console.print("Network execution: PERFORMED (single exact permitted action)")


@app.command("prepare-safe-assessment-run")
def prepare_safe_assessment_run_command(
    engagement_id: Annotated[str, typer.Option("--engagement-id")],
    action_paths: Annotated[
        list[Path], typer.Option("--action", help="Capability action YAML; repeatable")
    ],
    output: Annotated[Path, typer.Option("--output")],
    max_network_actions: Annotated[int, typer.Option("--max-network-actions")] = 20,
    max_errors: Annotated[int, typer.Option("--max-errors")] = 3,
) -> None:
    """Prepare a bounded multi-capability assessment plan; does not execute it."""
    intents = [
        build_execution_intent(engagement_id, load_model(path, CapabilityAction))
        for path in action_paths
    ]
    plan = build_assessment_execution_plan(
        engagement_id,
        intents,
        max_network_actions=max_network_actions,
        max_errors=max_errors,
        execution_enabled=False,
    )
    write_assessment_execution_plan(plan, output)
    console.print(f"Prepared intents: {len(intents)}")
    console.print("Execution enabled: NO")
    console.print("Network execution: NOT PERFORMED")


@app.command("show-safe-assessment-profile")
def show_safe_assessment_profile_command() -> None:
    """Show the autonomous ceiling for the current end-to-end safe mode."""
    profile = SafeAssessmentProfile()
    console.print_json(profile.model_dump_json())


@app.command("plan-safe-surface")
def plan_safe_surface_command(
    target: Annotated[str, typer.Argument(help="Initial HTTP(S) target")],
    output: Annotated[Path, typer.Option("--output", help="Write planned actions YAML here")],
) -> None:
    """Plan DNS/TLS/HTTP surface observations without executing them."""
    plan = plan_safe_surface_observations(target)
    dump_yaml(plan, output)
    console.print(f"Planned actions: {len(plan.actions)}")
    console.print("Fresh permit required per action: YES")
    console.print("Network execution: NOT PERFORMED")


@app.command("pentest-readiness")
def pentest_readiness_command() -> None:
    """Report whether ASTP can yet run a complete pentest/bug-hunt workflow."""
    readiness = current_pentest_readiness()
    console.print_json(readiness.model_dump_json())


@app.command("observe-authenticated-http")
def observe_authenticated_http_command(
    permit_path: Annotated[Path, typer.Argument(help="Signed execution permit YAML")],
    engagement_path: Annotated[Path, typer.Argument(help="Current engagement YAML")],
    test_path: Annotated[Path, typer.Argument(help="Current test definition YAML")],
    auth_session_path: Annotated[Path, typer.Argument(help="Origin-bound auth session YAML")],
    target: Annotated[str, typer.Option("--target", help="Exact HTTP(S) target URL")],
    http_method: Annotated[str, typer.Option("--http-method")] = "GET",
    requested_rps: Annotated[float | None, typer.Option("--rps")] = None,
    state_path: Annotated[Path, typer.Option("--state")] = DEFAULT_STATE_PATH,
    audit_path: Annotated[Path, typer.Option("--audit")] = DEFAULT_AUDIT_PATH,
    evidence_path: Annotated[Path | None, typer.Option("--evidence")] = None,
    manifest_path: Annotated[Path, typer.Option("--manifest")] = Path(".astp")
    / "evidence-manifest.jsonl",
    rate_state_path: Annotated[Path, typer.Option("--rate-state")] = Path(".astp")
    / "rate-state.json",
    runtime_db_path: Annotated[Path, typer.Option("--runtime-db")] = DEFAULT_RUNTIME_DB_PATH,
) -> None:
    """Perform one permit-gated authenticated GET/HEAD with origin-bound secret injection."""
    permit = load_model(permit_path, SignedExecutionPermit)
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    session = load_model(auth_session_path, AuthSessionProfile)
    _, keys = _permit_keyring()
    output = evidence_path or (
        Path(".astp") / "evidence" / f"authenticated-{permit.payload.permit_id}.json"
    )
    try:
        result = observe_authenticated_http(
            permit,
            engagement,
            test,
            keys,
            session,
            target=target,
            method=http_method,
            requested_rps=requested_rps,
            state_path=state_path,
            audit_path=audit_path,
            evidence_path=output,
            manifest_path=manifest_path,
            rate_state_path=rate_state_path,
            runtime_db_path=runtime_db_path,
        )
    except (ObservationError, ValueError) as exc:
        console.print(f"Authenticated observation completed: [bold]NO[/bold]\n{exc}")
        raise typer.Exit(code=6) from exc
    console.print("Authenticated observation completed: YES")
    console.print(f"Evidence ID: {result.evidence.evidence_id}")
    console.print("Request credentials persisted in evidence: NO")
    console.print("Permit consumed: YES")
    console.print("Network execution: authenticated observation-only GET/HEAD")


@app.command("plan-authorization-differential")
def plan_authorization_differential_command(
    target: Annotated[str, typer.Argument(help="Exact resource URL")],
    baseline_identity: Annotated[str, typer.Option("--baseline-identity")],
    comparison_identity: Annotated[str, typer.Option("--comparison-identity")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Prepare a two-identity authorization comparison; does not execute it."""
    plan = build_authorization_differential_plan(target, baseline_identity, comparison_identity)
    dump_yaml(plan, output)
    console.print(f"Differential plan: {plan.id}")
    console.print("Fresh permit per request: YES")
    console.print("Network execution: NOT PERFORMED")


@app.command("show-browser-worker-contract")
def show_browser_worker_contract_command() -> None:
    """Show the bounded browser worker contract and current runtime status."""
    console.print_json(BrowserWorkerContract().model_dump_json())


@app.command("show-external-adapter-contracts")
def show_external_adapter_contracts_command() -> None:
    """Show permit-first contracts for future external tool workers."""
    payload = [item.model_dump(mode="json") for item in builtin_external_adapter_contracts()]
    console.print_json(json.dumps(payload))


@app.command("prepare-verification-execution")
def prepare_verification_execution_command(
    candidate_path: Annotated[Path, typer.Argument()],
    action_path: Annotated[Path, typer.Argument()],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Bind an approved verification candidate to one exact capability action."""
    candidate = load_model(candidate_path, VerificationAuthorizationCandidate)
    action = load_model(action_path, CapabilityAction)
    envelope = prepare_verification_execution(candidate, action)
    dump_yaml(envelope, output)
    console.print(f"Verification envelope: {envelope.id}")
    console.print("Policy authorization still required: YES")
    console.print("Network execution: NOT PERFORMED")


@app.command("record-high-risk-approval")
def record_high_risk_approval_command(
    action_id: Annotated[str, typer.Option("--action-id")],
    operator: Annotated[str, typer.Option("--operator")],
    decision: Annotated[ApprovalDecision, typer.Option("--decision")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Record an exact-action human review without enabling autonomous execution."""
    approval = record_high_risk_approval(action_id, operator, decision)
    dump_yaml(approval, output)
    console.print(f"Approval: {approval.id}")
    console.print("Autonomous high-risk execution: NO")
    console.print("Network execution: NOT PERFORMED")


@app.command("assessment-coverage")
def assessment_coverage_command() -> None:
    """Show current assessment coverage dimensions."""
    coverage = current_assessment_coverage()
    payload = coverage.model_dump(mode="json")
    payload["completed_dimensions"] = coverage.completed_dimensions
    payload["total_dimensions"] = coverage.total_dimensions
    console.print_json(json.dumps(payload))


@app.command("prepare-end-to-end-assessment")
def prepare_end_to_end_assessment_command(
    engagement_id: Annotated[str, typer.Option("--engagement-id")],
    target: Annotated[str, typer.Option("--target")],
    output: Annotated[Path, typer.Option("--output")],
    auth_session_path: Annotated[Path | None, typer.Option("--auth-session")] = None,
) -> None:
    """Prepare the current maximum end-to-end assessment plan without execution."""
    session = load_model(auth_session_path, AuthSessionProfile) if auth_session_path else None
    plan = build_end_to_end_assessment_plan(engagement_id, target, auth_session=session)
    dump_yaml(plan, output)
    console.print(f"Assessment plan: {plan.id}")
    console.print(f"Unresolved capabilities: {len(plan.unresolved_capabilities)}")
    console.print("Network execution: NOT PERFORMED")


@app.command("build-retest-request")
def build_retest_request_command(
    finding_id: Annotated[str, typer.Argument()],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    """Create a retest request that requires current policy and a fresh permit."""
    request = build_retest_request(finding_id)
    dump_yaml(request, output)
    console.print(f"Retest request: {request.id}")
    console.print("Network execution: NOT PERFORMED")


@app.command("pentest-completion")
def pentest_completion_command() -> None:
    """State explicitly whether the full bug-hunt/pentest loop is complete."""
    console.print_json(evaluate_pentest_completion().model_dump_json())


@app.command("browser-runtime-status")
def browser_runtime_status_command() -> None:
    """Show whether the optional bounded browser runtime is locally available."""
    console.print_json(browser_runtime_status().model_dump_json())


@app.command("external-adapter-runtime-status")
def external_adapter_runtime_status_command() -> None:
    """Show local binary availability for bounded external adapter contracts."""
    payload = []
    for contract in builtin_external_adapter_contracts():
        item = contract.model_dump(mode="json")
        item["runtime_available"] = adapter_runtime_available(contract)
        payload.append(item)
    console.print_json(json.dumps(payload))


@app.command("compare-authorization-evidence")
def compare_authorization_evidence_command(
    baseline_path: Annotated[Path, typer.Argument(help="Baseline HTTP evidence JSON")],
    comparison_path: Annotated[Path, typer.Argument(help="Comparison HTTP evidence JSON")],
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    """Compare two already-captured authorization observations; performs no network I/O."""
    baseline = load_model(baseline_path, HttpObservationEvidence)
    comparison = load_model(comparison_path, HttpObservationEvidence)
    result = compare_authorization_evidence(baseline, comparison)
    if output is not None:
        dump_yaml(result, output)
    console.print_json(result.model_dump_json())
    console.print("Network execution: NOT PERFORMED")


if __name__ == "__main__":
    app()
