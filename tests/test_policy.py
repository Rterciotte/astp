from astp.models import (
    Decision,
    Engagement,
    EvaluationRequest,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
    TestDefinition as SecurityTestDefinition,
    evaluate_test,
    target_in_scope,
)


def engagement() -> Engagement:
    return Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value="*.example.com")],
            denied=[ScopeRule(kind=ScopeKind.DOMAIN, value="payments.example.com")],
        ),
    )


def make_test_definition(
    risk: RiskClass = RiskClass.SAFE_ACTIVE,
) -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="authorization.object_access",
        title="Object authorization",
        category="authorization",
        risk_class=risk,
        required_context=["authenticated_identity", "foreign_object_identifier"],
    )


def test_allowed_subdomain_is_in_scope() -> None:
    assert target_in_scope("https://api.example.com/users", engagement().scope)


def test_explicit_denial_overrides_wildcard() -> None:
    assert not target_in_scope("https://payments.example.com", engagement().scope)


def test_missing_context_blocks_execution() -> None:
    result = evaluate_test(
        engagement(),
        make_test_definition(),
        EvaluationRequest(
            target="https://api.example.com/users/1",
            available_context={"authenticated_identity"},
        ),
    )
    assert result.decision == Decision.INSUFFICIENT_CONTEXT
    assert result.missing_context == ["foreign_object_identifier"]


def test_safe_active_is_allowed_with_context() -> None:
    result = evaluate_test(
        engagement(),
        make_test_definition(),
        EvaluationRequest(
            target="https://api.example.com/users/1",
            available_context={"authenticated_identity", "foreign_object_identifier"},
        ),
    )
    assert result.decision == Decision.ALLOW


def test_intrusive_is_denied() -> None:
    result = evaluate_test(
        engagement(),
        make_test_definition(RiskClass.INTRUSIVE),
        EvaluationRequest(
            target="https://api.example.com/users/1",
            available_context={"authenticated_identity", "foreign_object_identifier"},
        ),
    )
    assert result.decision == Decision.DENY
