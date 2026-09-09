from astp.detector_policy import DetectorPolicyContext, MentionDisposition
from astp.detector_registry import builtin_detector_registry
from astp.orchestrator_scheduler import opportunities_from_signals


def test_signals_generate_only_matching_detector_opportunities() -> None:
    rows = opportunities_from_signals(
        program_id="local",
        target="http://local.test/reflect?q=x",
        signals=("reflected_parameter", "sql_parameter", "unrelated"),
        registry=builtin_detector_registry(),
        context=DetectorPolicyContext(
            disposition=MentionDisposition.EXPLICITLY_ALLOWED,
            target_in_scope=True,
            remaining_requests=100,
        ),
        remaining_budget=100,
    )

    assert {row.detector_id for row in rows} == {
        "dalfox.reflected-bounded.v1",
        "sqlmap.detect-bounded.v1",
    }


def test_explicit_scanner_denial_preserves_opportunity_but_blocks_execution() -> None:
    rows = opportunities_from_signals(
        program_id="denied",
        target="http://local.test/",
        signals=("known_cve",),
        registry=builtin_detector_registry(),
        context=DetectorPolicyContext(
            disposition=MentionDisposition.EXPLICITLY_DENIED,
            target_in_scope=True,
            remaining_requests=100,
        ),
        remaining_budget=100,
    )

    assert len(rows) == 1
    assert not rows[0].policy_decision.allowed
    assert rows[0].priority_score == -100
