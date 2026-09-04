from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from astp.models import (
    ApprovalArtifact,
    AssetConstraint,
    Decision,
    Engagement,
    EvaluationRequest,
    ScopeRule,
    TestDefinition,
    _match_rule,
)


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    REVIEW = "review"


class AuthorizationCheck(BaseModel):
    name: str
    status: CheckStatus
    message: str


class AuthorizationRequest(BaseModel):
    target: str
    available_context: set[str] = Field(default_factory=set)
    approvals: list[ApprovalArtifact] = Field(default_factory=list)
    http_method: str | None = None
    identity: str | None = None
    requested_requests_per_second: float | None = Field(default=None, gt=0, le=1000)
    now: datetime | None = None


class AuthorizationResult(BaseModel):
    decision: Decision
    checks: list[AuthorizationCheck] = Field(default_factory=list)
    missing_context: list[str] = Field(default_factory=list)
    approval_ids: list[str] = Field(default_factory=list)
    effective_max_requests_per_second: float | None = None


def _matching_rules(target: str, rules: list[ScopeRule]) -> list[ScopeRule]:
    return [rule for rule in rules if _match_rule(target, rule)]


def _matching_asset_constraints(
    target: str, constraints: list[AssetConstraint]
) -> list[AssetConstraint]:
    return [constraint for constraint in constraints if _match_rule(target, constraint.selector)]


def _target_path(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    return parsed.path or "/"


def _target_port(target: str) -> int:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.port is not None:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def _path_matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(f"{normalized}/")


def _approval_matches(
    approval: ApprovalArtifact,
    engagement: Engagement,
    test: TestDefinition,
    request: AuthorizationRequest,
) -> bool:
    now = request.now or datetime.now(timezone.utc)
    if approval.engagement_id != engagement.id or not approval.is_active(now):
        return False
    if not any(_match_rule(request.target, rule) for rule in approval.targets):
        return False
    if approval.test_ids and test.id not in approval.test_ids:
        return False
    if approval.risk_classes and test.risk_class not in approval.risk_classes:
        return False
    if approval.identities and request.identity not in approval.identities:
        return False
    return not (
        approval.max_requests_per_second is not None
        and request.requested_requests_per_second is not None
        and request.requested_requests_per_second > approval.max_requests_per_second
    )


def _valid_approvals(
    engagement: Engagement,
    test: TestDefinition,
    request: AuthorizationRequest,
) -> list[ApprovalArtifact]:
    return [
        approval
        for approval in request.approvals
        if _approval_matches(approval, engagement, test, request)
    ]


def _check_asset_constraints(
    engagement: Engagement,
    request: AuthorizationRequest,
    checks: list[AuthorizationCheck],
) -> Decision | None:
    matching = _matching_asset_constraints(request.target, engagement.constraints.assets)
    if not matching:
        return None

    path = _target_path(request.target)
    port = _target_port(request.target)
    method = request.http_method.upper() if request.http_method else None

    for constraint in matching:
        if any(_path_matches(path, prefix) for prefix in constraint.denied_paths):
            checks.append(
                AuthorizationCheck(
                    name="path_policy",
                    status=CheckStatus.FAIL,
                    message=f"Path '{path}' matches an explicit asset-level deny rule.",
                )
            )
            return Decision.DENY

        if constraint.allowed_paths and not any(
            _path_matches(path, prefix) for prefix in constraint.allowed_paths
        ):
            checks.append(
                AuthorizationCheck(
                    name="path_policy",
                    status=CheckStatus.FAIL,
                    message=f"Path '{path}' is outside the asset's allowed path prefixes.",
                )
            )
            return Decision.DENY

        if constraint.allowed_ports and port not in constraint.allowed_ports:
            checks.append(
                AuthorizationCheck(
                    name="port_policy",
                    status=CheckStatus.FAIL,
                    message=f"Port {port} is not authorized for this asset.",
                )
            )
            return Decision.DENY

        if constraint.allowed_http_methods:
            if method is None:
                checks.append(
                    AuthorizationCheck(
                        name="http_method_policy",
                        status=CheckStatus.REVIEW,
                        message="HTTP method is required to evaluate this asset policy.",
                    )
                )
                return Decision.INSUFFICIENT_CONTEXT
            if method not in constraint.allowed_http_methods:
                checks.append(
                    AuthorizationCheck(
                        name="http_method_policy",
                        status=CheckStatus.FAIL,
                        message=f"HTTP method '{method}' is not authorized for this asset.",
                    )
                )
                return Decision.DENY

        if constraint.allowed_identities:
            if request.identity is None:
                checks.append(
                    AuthorizationCheck(
                        name="identity_policy",
                        status=CheckStatus.REVIEW,
                        message="Identity is required to evaluate this asset policy.",
                    )
                )
                return Decision.INSUFFICIENT_CONTEXT
            if request.identity not in constraint.allowed_identities:
                checks.append(
                    AuthorizationCheck(
                        name="identity_policy",
                        status=CheckStatus.FAIL,
                        message=f"Identity '{request.identity}' is not authorized for this asset.",
                    )
                )
                return Decision.DENY

    checks.append(
        AuthorizationCheck(
            name="asset_constraints",
            status=CheckStatus.PASS,
            message="Target satisfies all matching asset-level constraints.",
        )
    )
    return None


def _effective_rate_limit(
    engagement: Engagement,
    request: AuthorizationRequest,
    approvals: list[ApprovalArtifact],
) -> float:
    limits = [engagement.constraints.max_requests_per_second]
    limits.extend(
        constraint.max_requests_per_second
        for constraint in _matching_asset_constraints(
            request.target, engagement.constraints.assets
        )
        if constraint.max_requests_per_second is not None
    )
    limits.extend(
        approval.max_requests_per_second
        for approval in approvals
        if approval.max_requests_per_second is not None
    )
    return min(limits)


def authorize_test(
    engagement: Engagement,
    test: TestDefinition,
    request: AuthorizationRequest,
) -> AuthorizationResult:
    checks: list[AuthorizationCheck] = []
    approvals = _valid_approvals(engagement, test, request)
    approval_ids = [approval.id for approval in approvals]

    denied = _matching_rules(request.target, engagement.scope.denied)
    if denied:
        checks.append(
            AuthorizationCheck(
                name="target_scope",
                status=CheckStatus.FAIL,
                message="Target matches an explicit deny rule.",
            )
        )
        return AuthorizationResult(decision=Decision.DENY, checks=checks)

    allowed = _matching_rules(request.target, engagement.scope.allowed)
    conditional = _matching_rules(request.target, engagement.scope.approval_required)

    if conditional and not allowed:
        if not approvals:
            checks.append(
                AuthorizationCheck(
                    name="target_scope",
                    status=CheckStatus.REVIEW,
                    message=(
                        "Target is conditionally authorized and needs a matching "
                        "approval artifact."
                    ),
                )
            )
            return AuthorizationResult(
                decision=Decision.APPROVAL_REQUIRED,
                checks=checks,
            )
        checks.append(
            AuthorizationCheck(
                name="target_scope",
                status=CheckStatus.PASS,
                message="A valid bounded approval satisfies the target-level condition.",
            )
        )
    elif allowed:
        checks.append(
            AuthorizationCheck(
                name="target_scope",
                status=CheckStatus.PASS,
                message="Target matches an explicit allow rule.",
            )
        )
    else:
        checks.append(
            AuthorizationCheck(
                name="target_scope",
                status=CheckStatus.FAIL,
                message="Target does not match an authorized scope rule.",
            )
        )
        return AuthorizationResult(decision=Decision.DENY, checks=checks)

    constraint_decision = _check_asset_constraints(engagement, request, checks)
    if constraint_decision is not None:
        return AuthorizationResult(decision=constraint_decision, checks=checks)

    missing = sorted(set(test.required_context) - request.available_context)
    if missing:
        checks.append(
            AuthorizationCheck(
                name="required_context",
                status=CheckStatus.FAIL,
                message="Required test context is missing.",
            )
        )
        return AuthorizationResult(
            decision=Decision.INSUFFICIENT_CONTEXT,
            checks=checks,
            missing_context=missing,
        )

    checks.append(
        AuthorizationCheck(
            name="required_context",
            status=CheckStatus.PASS,
            message="All required test context is available.",
        )
    )

    method_decision = engagement.methods.decision_for(test.risk_class)
    if method_decision == Decision.DENY:
        checks.append(
            AuthorizationCheck(
                name="risk_policy",
                status=CheckStatus.FAIL,
                message=f"Risk class '{test.risk_class.value}' is denied by policy.",
            )
        )
        return AuthorizationResult(decision=Decision.DENY, checks=checks)

    if method_decision == Decision.APPROVAL_REQUIRED and not approvals:
        checks.append(
            AuthorizationCheck(
                name="risk_policy",
                status=CheckStatus.REVIEW,
                message=(
                    f"Risk class '{test.risk_class.value}' requires a matching approval artifact."
                ),
            )
        )
        return AuthorizationResult(
            decision=Decision.APPROVAL_REQUIRED,
            checks=checks,
        )

    checks.append(
        AuthorizationCheck(
            name="risk_policy",
            status=CheckStatus.PASS,
            message=(
                "Risk policy allows this test."
                if method_decision == Decision.ALLOW
                else "A valid bounded approval satisfies the risk-policy condition."
            ),
        )
    )

    effective_rate = _effective_rate_limit(engagement, request, approvals)
    if (
        request.requested_requests_per_second is not None
        and request.requested_requests_per_second > effective_rate
    ):
        checks.append(
            AuthorizationCheck(
                name="rate_limit",
                status=CheckStatus.FAIL,
                message=(
                    f"Requested rate {request.requested_requests_per_second:g} req/s exceeds "
                    f"the effective limit of {effective_rate:g} req/s."
                ),
            )
        )
        return AuthorizationResult(
            decision=Decision.DENY,
            checks=checks,
            approval_ids=approval_ids,
            effective_max_requests_per_second=effective_rate,
        )

    checks.append(
        AuthorizationCheck(
            name="rate_limit",
            status=CheckStatus.PASS,
            message=f"Effective maximum rate is {effective_rate:g} req/s.",
        )
    )
    return AuthorizationResult(
        decision=Decision.ALLOW,
        checks=checks,
        approval_ids=approval_ids,
        effective_max_requests_per_second=effective_rate,
    )


def from_evaluation_request(request: EvaluationRequest) -> AuthorizationRequest:
    return AuthorizationRequest(
        target=request.target,
        available_context=request.available_context,
    )
