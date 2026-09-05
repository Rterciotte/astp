import json
import os
import secrets
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from astp.adapter_registry import builtin_adapter_registry, ensure_adapter_compatible
from astp.authorization import AuthorizationRequest, authorize_test
from astp.autonomy_session import prepare_autonomy_session
from astp.browser_intake import capture_to_text, load_capture
from astp.circuit_breaker import FailureCircuitBreaker
from astp.controlled_loop import run_controlled_queue
from astp.evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from astp.evidence_store import SensitivityLabel, verify_evidence_manifest
from astp.execution_trace import append_trace_event, verify_execution_trace
from astp.feedback import apply_evidence_feedback
from astp.findings import FindingCandidate, FindingSet, correlate_findings
from astp.frontier import build_frontier
from astp.hypothesis import build_observation_hypotheses
from astp.io import dump_yaml, load_model, load_yaml
from astp.lifecycle import (
    append_audit_event,
    consume_execution_permit,
    permit_status,
    revoke_permit,
    verify_audit_chain,
)
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
from astp.observation import (
    DEFAULT_MAX_BODY_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    HttpObservationEvidence,
    ObservationError,
    observe_http,
    verify_observation_evidence,
)
from astp.permit_broker import broker_queue_item_permit
from astp.permits import (
    DEFAULT_PERMIT_TTL_SECONDS,
    PermitVerificationRequest,
    SignedExecutionPermit,
    issue_execution_permit,
    verify_execution_permit,
)
from astp.planner import ObservationPlan, build_observation_plan
from astp.planner_state import get_planner_state, initialize_planner_state
from astp.policy_snapshot import capture_policy_snapshot
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
from astp.reporting import render_markdown_report
from astp.result_interpreter import interpret_observation
from astp.resume_guard import evaluate_resume
from astp.runtime_state import revoke_runtime_permit, runtime_permit_status
from astp.scope_compiler import CompilationStatus, compile_scope_file
from astp.security_graph import build_security_graph
from astp.session_budget import SessionBudget
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


if __name__ == "__main__":
    app()
