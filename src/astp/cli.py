import json
import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from astp.authorization import AuthorizationRequest, authorize_test
from astp.io import dump_yaml, load_model
from astp.lifecycle import (
    append_audit_event,
    consume_execution_permit,
    permit_status,
    revoke_permit,
    verify_audit_chain,
)
from astp.models import (
    ApprovalArtifact,
    Decision,
    Engagement,
    EvaluationRequest,
    TestDefinition,
    evaluate_test,
)
from astp.permits import (
    DEFAULT_PERMIT_TTL_SECONDS,
    PermitVerificationRequest,
    SignedExecutionPermit,
    issue_execution_permit,
    verify_execution_permit,
)
from astp.scope_compiler import CompilationStatus, compile_scope_file

app = typer.Typer(
    help=(
        "ASTP policy-first security testing foundation. "
        "Offensive execution is not implemented yet."
    )
)
console = Console()


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
) -> None:
    """Produce an auditable authorization decision without executing a test."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    approvals = [
        load_model(path, ApprovalArtifact) for path in (approval_path or [])
    ]
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
    console.print("Execution: DISABLED (Milestone 1.4)")
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
            isinstance(key_id, str) and isinstance(value, str)
            for key_id, value in raw.items()
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
    ttl_seconds: Annotated[
        int,
        typer.Option("--ttl-seconds", help="Permit lifetime in seconds; maximum 900"),
    ] = DEFAULT_PERMIT_TTL_SECONDS,
    audit_path: Annotated[
        Path,
        typer.Option("--audit", help="Append-only audit log"),
    ] = Path(".astp") / "audit.jsonl",
) -> None:
    """Authorize an exact action and issue a short-lived signed execution permit."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    approvals = [
        load_model(path, ApprovalArtifact) for path in (approval_path or [])
    ]
    request = AuthorizationRequest(
        target=target,
        available_context=set(context or []),
        approvals=approvals,
        http_method=http_method,
        identity=identity,
        requested_requests_per_second=requested_rps,
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
        },
    )
    console.print("[bold green]Execution permit issued.[/bold green]")
    console.print(f"Permit ID: {permit.payload.permit_id}")
    console.print(f"Expires at: {permit.payload.expires_at.isoformat()}")
    console.print(
        f"Maximum rate: {permit.payload.max_requests_per_second:g} req/s"
    )
    console.print(f"Written to: {output}")
    console.print("Execution remains DISABLED (Milestone 1.4).")


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
    console.print("Execution remains DISABLED (Milestone 1.4).")
    if not result.valid:
        raise typer.Exit(code=3)


def _default_state_path() -> Path:
    return Path(".astp") / "permit-state.json"


def _default_audit_path() -> Path:
    return Path(".astp") / "audit.jsonl"


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
    ] = _default_state_path(),
    audit_path: Annotated[
        Path, typer.Option("--audit", help="Append-only audit log")
    ] = _default_audit_path(),
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
    console.print("Execution remains DISABLED (Milestone 1.4).")
    if not result.accepted:
        raise typer.Exit(code=4)


@app.command("revoke-permit")
def revoke_permit_command(
    permit_id: Annotated[str, typer.Argument(help="Permit ID to revoke")],
    reason: Annotated[str, typer.Option("--reason", help="Human-readable revocation reason")],
    state_path: Annotated[
        Path, typer.Option("--state", help="Permit lifecycle state file")
    ] = _default_state_path(),
    audit_path: Annotated[
        Path, typer.Option("--audit", help="Append-only audit log")
    ] = _default_audit_path(),
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
    ] = _default_state_path(),
) -> None:
    """Show local lifecycle state for a permit."""
    console.print(permit_status(state_path, permit_id).value.upper())


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
    table.add_row("Execution", "DISABLED (Milestone 1)")
    table.add_row(
        "Missing context",
        ", ".join(result.missing_context) or "none",
    )

    console.print(table)

    for reason in result.reasons:
        console.print(f"- {reason}")


if __name__ == "__main__":
    app()
