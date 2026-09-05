from datetime import UTC, datetime

from astp.planner_state import PlannerItemState, PlannerStateEntry
from astp.resume_guard import evaluate_resume


def entry(queue_id, state):
    return PlannerStateEntry(
        queue_id=queue_id, state=state, attempts=0, updated_at=datetime.now(UTC)
    )


def test_resume_guard_never_blindly_resumes_consumed_states():
    result = evaluate_resume(
        [
            entry("q1", PlannerItemState.QUEUED),
            entry("q2", PlannerItemState.COMPLETED),
            entry("q3", PlannerItemState.PERMIT_ISSUED),
        ]
    )
    assert result.allowed is True
    assert result.resumable_queue_ids == ["q1"]
    assert result.blocked_queue_ids == ["q2", "q3"]
