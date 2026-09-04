from datetime import UTC, datetime

from astp.autonomy_session import prepare_autonomy_session
from astp.session_budget import SessionBudget
from astp.work_queue import WorkQueue, WorkQueueItem


def test_session_preparation_never_enables_execution():
    q = WorkQueue(
        created_at=datetime.now(UTC),
        max_active_programs=1,
        items=[
            WorkQueueItem(
                queue_id="q",
                engagement_id="e",
                test_id="t",
                plan_item_id="p",
                target="https://example.com",
                method="GET",
            )
        ],
    )
    result = prepare_autonomy_session(q, SessionBudget(max_actions=1))
    assert len(result.items) == 1
    assert result.execution_enabled is False
    assert result.items[0].requires_fresh_permit
