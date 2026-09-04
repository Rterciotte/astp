from datetime import UTC, datetime, timedelta

from astp.authorization import AuthorizationRequest, authorize_test
from astp.models import Decision, OperationalStatus, RiskClass, SemanticExclusionKind
from astp.models import TestDefinition as ASTPTestDefinition
from astp.observation import observation_user_agent
from astp.permits import issue_execution_permit
from astp.program_intake import (
    compile_program,
    import_program_text,
    resolve_issue_with_semantic_exclusion,
    resolve_rate_issue,
)
from astp.program_runtime import create_operational_attestation

PROGRAM = """
Programa Público
2.5. Recomendamos que os analistas usem o User Agent: Bughunt - Security Research.
2.6. É explicitamente proibido realizar ataques no escopo quando o programa estiver offline.
5.37. Uso de ferramentas automatizadas que podem gerar tráfego significativo e possivelmente
prejudicar o funcionamento de nossa aplicação.
1.1. EXCLUSÃO DE ENDPOINTS / ATIVOS
Qualquer sistema relacionado à Universidade Smart Fit, independentemente do país
Escopo
*.smartfit.com.br
"""


def _reviewed_program():
    program = import_program_text(PROGRAM, name="Smart Fit", platform="bughunt")
    resolve_rate_issue(program, 1.0)
    issue_index = next(
        index
        for index, issue in enumerate(program.issues, 1)
        if issue.code == "broad_asset_exclusion"
    )
    resolve_issue_with_semantic_exclusion(
        program,
        issue_index=issue_index,
        kind=SemanticExclusionKind.PRODUCT_FAMILY,
        value="Universidade Smart Fit",
    )
    return program


def _test_definition():
    return ASTPTestDefinition(
        id="http.observation",
        title="HTTP observation",
        category="discovery",
        risk_class=RiskClass.SAFE_ACTIVE,
    )


def _request(program, *, attestation=None, now=None):
    engagement = compile_program(program)
    return engagement, AuthorizationRequest(
        target="https://www.smartfit.com.br/",
        http_method="GET",
        requested_requests_per_second=1.0,
        semantic_exclusion_clears={rule.id for rule in engagement.constraints.semantic_exclusions},
        program_operational_attestation=attestation,
        now=now,
    )


def test_compile_program_preserves_runtime_policy_metadata() -> None:
    program = _reviewed_program()
    engagement = compile_program(program)

    assert engagement.program is not None
    assert engagement.program.program_id == program.id
    assert engagement.program.source_content_sha256 == program.source.content_sha256
    assert engagement.program.requires_online is True
    assert engagement.program.recommended_user_agent == "Bughunt - Security Research"
    assert engagement.constraints.max_requests_per_second == 1.0


def test_online_required_program_blocks_without_attestation() -> None:
    program = _reviewed_program()
    engagement, request = _request(program)

    result = authorize_test(engagement, _test_definition(), request)

    assert result.decision == Decision.INSUFFICIENT_CONTEXT
    assert any(check.name == "program_operational_status" for check in result.checks)


def test_offline_attestation_denies_execution() -> None:
    program = _reviewed_program()
    now = datetime(2026, 9, 4, 16, 30, tzinfo=UTC)
    attestation = create_operational_attestation(
        program,
        status=OperationalStatus.OFFLINE,
        source_type="operator",
        observed_at=now,
    )
    engagement, request = _request(program, attestation=attestation, now=now)

    result = authorize_test(engagement, _test_definition(), request)

    assert result.decision == Decision.DENY


def test_stale_online_attestation_is_insufficient_context() -> None:
    program = _reviewed_program()
    observed = datetime(2026, 9, 4, 16, 0, tzinfo=UTC)
    attestation = create_operational_attestation(
        program,
        status=OperationalStatus.ONLINE,
        source_type="operator",
        observed_at=observed,
    )
    engagement, request = _request(
        program,
        attestation=attestation,
        now=observed + timedelta(minutes=6),
    )

    result = authorize_test(engagement, _test_definition(), request)

    assert result.decision == Decision.INSUFFICIENT_CONTEXT


def test_online_attestation_allows_and_caps_permit_lifetime() -> None:
    program = _reviewed_program()
    now = datetime(2026, 9, 4, 16, 30, tzinfo=UTC)
    attestation = create_operational_attestation(
        program,
        status=OperationalStatus.ONLINE,
        source_type="authenticated_browser",
        observed_at=now - timedelta(minutes=4),
    )
    engagement, request = _request(program, attestation=attestation, now=now)

    result = authorize_test(engagement, _test_definition(), request)
    assert result.decision == Decision.ALLOW
    assert result.operational_attestation_id == attestation.id

    permit = issue_execution_permit(
        engagement,
        _test_definition(),
        request,
        "x" * 48,
        ttl_seconds=300,
        now=now,
    )
    assert permit.payload.operational_attestation_id == attestation.id
    assert permit.payload.expires_at == now + timedelta(minutes=1)


def test_observation_uses_program_recommended_user_agent() -> None:
    engagement = compile_program(_reviewed_program())
    assert observation_user_agent(engagement) == "Bughunt - Security Research"
