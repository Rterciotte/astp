from datetime import UTC, datetime

from astp.planner_state import (
    PlannerItemState,
    get_planner_state,
    initialize_planner_state,
    transition_planner_state,
)
from astp.work_queue import WorkQueue, WorkQueueItem


def test_durable_state_transitions(tmp_path):
    queue = WorkQueue(
        created_at=datetime.now(UTC),
        max_active_programs=1,
        items=[
            WorkQueueItem(
                queue_id="q1",
                engagement_id="e",
                test_id="t",
                plan_item_id="p",
                target="https://example.com",
                method="GET",
            )
        ],
    )
    db = tmp_path / "planner.db"
    initialize_planner_state(db, queue)
    assert get_planner_state(db, "q1").state == PlannerItemState.QUEUED
    transition_planner_state(db, "q1", PlannerItemState.PERMIT_ISSUED, permit_id="p1")
    transition_planner_state(db, "q1", PlannerItemState.RUNNING)
    entry = transition_planner_state(db, "q1", PlannerItemState.COMPLETED, evidence_id="e1")
    assert entry.evidence_id == "e1"
    assert entry.attempts == 1


def test_invalid_transition_rejected(tmp_path):
    queue = WorkQueue(
        created_at=datetime.now(UTC),
        max_active_programs=1,
        items=[
            WorkQueueItem(
                queue_id="q1",
                engagement_id="e",
                test_id="t",
                plan_item_id="p",
                target="https://example.com",
                method="GET",
            )
        ],
    )
    db = tmp_path / "planner.db"
    initialize_planner_state(db, queue)
    try:
        transition_planner_state(db, "q1", PlannerItemState.COMPLETED)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
