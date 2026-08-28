import os
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from astp.authorization import AuthorizationRequest, authorize_test
from astp.io import dump_yaml, load_model
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
    approvals = [load_model(path, ApprovalArtifact) for path in (approval_path or [])]
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
    console.print("Execution: DISABLED (Milestone 1.3)")
    if result.approval_ids:
        console.print(f"Approval artifacts: {', '.join(result.approval_ids)}")
    if result.effective_max_requests_per_second is not None:
        rate = result.effective_max_requests_per_second
        console.print(f"Effective rate limit: {rate:g} req/s")
    if result.missing_context:
        console.print(f"Missing context: {', '.join(result.missing_context)}")


def _permit_key() -> str:
    key = os.environ.get("ASTP_PERMIT_KEY")
    if not key:
        raise typer.BadParameter("ASTP_PERMIT_KEY is required and must contain at least 32 bytes.")
    return key


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
) -> None:
    """Authorize an exact action and issue a short-lived signed execution permit."""
    engagement = load_model(engagement_path, Engagement)
    test = load_model(test_path, TestDefinition)
    approvals = [load_model(path, ApprovalArtifact) for path in (approval_path or [])]
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

    try:
        permit = issue_execution_permit(
            engagement,
            test,
            request,
            _permit_key(),
            ttl_seconds=ttl_seconds,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    dump_yaml(permit, output)
    console.print("[bold green]Execution permit issued.[/bold green]")
    console.print(f"Permit ID: {permit.payload.permit_id}")
    console.print(f"Expires at: {permit.payload.expires_at.isoformat()}")
    console.print(f"Maximum rate: {permit.payload.max_requests_per_second:g} req/s")
    console.print(f"Written to: {output}")
    console.print("Execution remains DISABLED (Milestone 1.3).")


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
            _permit_key(),
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
    console.print("Execution remains DISABLED (Milestone 1.3).")
    if not result.valid:
        raise typer.Exit(code=3)


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
