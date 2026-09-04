from datetime import datetime, timedelta, timezone

from astp.authorization import AuthorizationRequest, CheckStatus, authorize_test
from astp.models import (
    ApprovalArtifact,
    AssetConstraint,
    Constraints,
    Decision,
    Engagement,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
    TestDefinition as SecurityTestDefinition,
)


def make_test(risk: RiskClass = RiskClass.SAFE_ACTIVE) -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="authorization.object_access",
        title="Object authorization",
        category="authorization",
        risk_class=risk,
        required_context=["authenticated_identity"],
    )


def approval(
    *,
    engagement_id: str = "e1",
    target: str = "api.example.com",
    test_id: str = "authorization.object_access",
    risk: RiskClass = RiskClass.SAFE_ACTIVE,
    identity: str | None = None,
    expired: bool = False,
    rps: float | None = None,
) -> ApprovalArtifact:
    now = datetime.now(timezone.utc)
    issued = now - timedelta(days=2 if expired else 1)
    expires = now - timedelta(days=1) if expired else now + timedelta(days=1)
    return ApprovalArtifact(
        id="approval-1",
        engagement_id=engagement_id,
        actor="owner@example.com",
        issued_at=issued,
        expires_at=expires,
        targets=(ScopeRule(kind=ScopeKind.DOMAIN, value=target),),
        test_ids=(test_id,),
        risk_classes=(risk,),
        identities=(identity,) if identity else (),
        max_requests_per_second=rps,
    )


def test_explicit_deny_wins_over_allow() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.WILDCARD_DOMAIN, value="*.example.com")],
            denied=[ScopeRule(kind=ScopeKind.DOMAIN, value="admin.example.com")],
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://admin.example.com",
            available_context={"authenticated_identity"},
        ),
    )
    assert result.decision == Decision.DENY
    assert result.checks[0].status == CheckStatus.FAIL


def test_target_level_approval_requires_artifact() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            approval_required=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com",
            available_context={"authenticated_identity"},
        ),
    )
    assert result.decision == Decision.APPROVAL_REQUIRED
    assert result.checks[0].status == CheckStatus.REVIEW


def test_matching_approval_can_satisfy_target_condition() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            approval_required=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com",
            available_context={"authenticated_identity"},
            approvals=[approval()],
        ),
    )
    assert result.decision == Decision.ALLOW
    assert result.approval_ids == ["approval-1"]


def test_expired_approval_does_not_authorize() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            approval_required=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com",
            available_context={"authenticated_identity"},
            approvals=[approval(expired=True)],
        ),
    )
    assert result.decision == Decision.APPROVAL_REQUIRED


def test_approval_is_bound_to_engagement() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            approval_required=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com",
            available_context={"authenticated_identity"},
            approvals=[approval(engagement_id="other")],
        ),
    )
    assert result.decision == Decision.APPROVAL_REQUIRED


def test_denied_path_wins_inside_allowed_asset() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
        constraints=Constraints(
            assets=[
                AssetConstraint(
                    selector=ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com"),
                    allowed_paths=["/v1"],
                    denied_paths=["/v1/admin"],
                )
            ]
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com/v1/admin/users",
            available_context={"authenticated_identity"},
        ),
    )
    assert result.decision == Decision.DENY
    assert result.checks[-1].name == "path_policy"


def test_http_method_identity_port_and_rate_are_enforced() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
        constraints=Constraints(
            max_requests_per_second=5,
            assets=[
                AssetConstraint(
                    selector=ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com"),
                    allowed_paths=["/v1"],
                    allowed_ports=[443],
                    allowed_http_methods=["GET"],
                    allowed_identities=["researcher"],
                    max_requests_per_second=2,
                )
            ],
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com/v1/users",
            available_context={"authenticated_identity"},
            http_method="GET",
            identity="researcher",
            requested_requests_per_second=2,
        ),
    )
    assert result.decision == Decision.ALLOW
    assert result.effective_max_requests_per_second == 2


def test_missing_http_method_is_insufficient_context_when_policy_requires_it() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
        constraints=Constraints(
            assets=[
                AssetConstraint(
                    selector=ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com"),
                    allowed_http_methods=["GET"],
                )
            ]
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com/v1/users",
            available_context={"authenticated_identity"},
        ),
    )
    assert result.decision == Decision.INSUFFICIENT_CONTEXT


def test_requested_rate_above_asset_limit_is_denied() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
        constraints=Constraints(
            max_requests_per_second=5,
            assets=[
                AssetConstraint(
                    selector=ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com"),
                    max_requests_per_second=1,
                )
            ],
        ),
    )
    result = authorize_test(
        engagement,
        make_test(),
        AuthorizationRequest(
            target="https://api.example.com/v1/users",
            available_context={"authenticated_identity"},
            requested_requests_per_second=2,
        ),
    )
    assert result.decision == Decision.DENY
    assert result.checks[-1].name == "rate_limit"


def test_risk_level_approval_is_independent_and_bounded() -> None:
    engagement = Engagement(
        id="e1",
        name="test",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="api.example.com")]
        ),
    )
    result = authorize_test(
        engagement,
        make_test(RiskClass.STATE_CHANGING),
        AuthorizationRequest(
            target="https://api.example.com",
            available_context={"authenticated_identity"},
            approvals=[approval(risk=RiskClass.STATE_CHANGING)],
        ),
    )
    assert result.decision == Decision.ALLOW
