from datetime import UTC, datetime, timedelta

from astp.session_budget import SessionBudget, SessionCounters, StopReason, evaluate_budget


def test_budget_stops_on_request_limit():
    now = datetime.now(UTC)
    result = evaluate_budget(
        SessionBudget(max_requests=2), SessionCounters(started_at=now, requests=2), now=now
    )
    assert not result.allowed
    assert StopReason.REQUEST_BUDGET in result.reasons


def test_budget_stops_on_wall_clock():
    now = datetime.now(UTC)
    result = evaluate_budget(
        SessionBudget(max_wall_clock_seconds=10),
        SessionCounters(started_at=now - timedelta(seconds=11)),
        now=now,
    )
    assert StopReason.WALL_CLOCK in result.reasons
