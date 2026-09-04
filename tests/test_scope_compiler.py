from astp.models import Decision, ScopeKind
from astp.scope_compiler import CompilationStatus, compile_scope_text


def test_compiles_explicit_allow_and_exception() -> None:
    result = compile_scope_text("*.example.com is in scope except payments.example.com.")

    assert result.status == CompilationStatus.CLEAN
    assert [(rule.kind, rule.value) for rule in result.engagement.scope.allowed] == [
        (ScopeKind.WILDCARD_DOMAIN, "*.example.com")
    ]
    assert [(rule.kind, rule.value) for rule in result.engagement.scope.denied] == [
        (ScopeKind.DOMAIN, "payments.example.com")
    ]


def test_compiles_rate_limit() -> None:
    result = compile_scope_text(
        "example.com is in scope. Testing should not exceed 5 requests per second."
    )

    assert result.engagement.constraints.max_requests_per_second == 5.0


def test_compiles_prohibitions_conservatively() -> None:
    result = compile_scope_text(
        "example.com is in scope. DoS and social engineering are prohibited. "
        "Actions affecting production data are prohibited."
    )

    assert result.engagement.constraints.no_dos is True
    assert result.engagement.constraints.no_social_engineering is True
    assert result.engagement.constraints.no_data_destruction is True
    assert result.engagement.methods.intrusive == Decision.DENY


def test_ambiguous_scope_is_not_inferred_as_permission() -> None:
    result = compile_scope_text(
        "*.example.com is generally in scope unless a service owner says otherwise."
    )

    assert result.status == CompilationStatus.NEEDS_REVIEW
    assert result.engagement.scope.allowed == []
    assert {issue.code for issue in result.issues} >= {
        "ambiguous_scope_language",
        "no_explicit_allowed_scope",
    }


def test_target_without_scope_cue_requires_review() -> None:
    result = compile_scope_text("Production API: api.example.com")

    assert result.status == CompilationStatus.NEEDS_REVIEW
    assert result.engagement.scope.allowed == []
    assert "unclassified_target" in {issue.code for issue in result.issues}


def test_explicit_out_of_scope_is_denied() -> None:
    result = compile_scope_text("example.com is in scope. legacy.example.com is out of scope.")

    assert result.engagement.scope.denied[0].value == "legacy.example.com"


def test_url_and_cidr_are_supported() -> None:
    result = compile_scope_text(
        "https://api.example.com/v1 is in scope. 10.20.0.0/16 is out of scope."
    )

    assert result.engagement.scope.allowed[0].kind == ScopeKind.URL_PREFIX
    assert result.engagement.scope.allowed[0].value == "https://api.example.com/v1"
    assert result.engagement.scope.denied[0].kind == ScopeKind.CIDR
    assert result.engagement.scope.denied[0].value == "10.20.0.0/16"


def test_prior_approval_becomes_conditional_scope() -> None:
    result = compile_scope_text("api.example.com may be tested with prior approval.")

    assert result.status == CompilationStatus.CLEAN
    assert result.engagement.scope.allowed == []
    assert [(rule.kind, rule.value) for rule in result.engagement.scope.approval_required] == [
        (ScopeKind.DOMAIN, "api.example.com")
    ]
    assert result.extracted_rules[0].rule_type == "scope.approval_required"
