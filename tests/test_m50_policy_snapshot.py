import pytest

from astp.models import (
    Constraints,
    Engagement,
    MethodPolicy,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import TestDefinition as RuntimeTestDefinition
from astp.policy_snapshot import assert_policy_unchanged, capture_policy_snapshot


def test_policy_snapshot_detects_drift():
    engagement = Engagement(
        id="e",
        name="e",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.com")]),
        methods=MethodPolicy(),
        constraints=Constraints(),
    )
    test = RuntimeTestDefinition(
        id="t", title="t", category="observation", risk_class=RiskClass.SAFE_ACTIVE
    )
    snapshot = capture_policy_snapshot(engagement, test)
    assert_policy_unchanged(snapshot, engagement, test)
    changed = engagement.model_copy(update={"name": "changed"})
    with pytest.raises(ValueError, match="policy drift"):
        assert_policy_unchanged(snapshot, changed, test)
