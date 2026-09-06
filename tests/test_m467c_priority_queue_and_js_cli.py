from datetime import UTC, datetime
from pathlib import Path

from astp.js_static_analysis import analyze_javascript_file
from astp.models import Decision
from astp.planner import ObservationPlan, ObservationPlanItem, PlanItemStatus
from astp.priority_work_queue import build_priority_work_queue


def _plan() -> ObservationPlan:
    return ObservationPlan(
        engagement_id="e",
        test_id="t",
        created_at=datetime(2026, 9, 6, tzinfo=UTC),
        items=[
            ObservationPlanItem(
                id="root",
                target="https://www.example.com/",
                status=PlanItemStatus.AUTHORIZABLE,
                authorization_decision=Decision.ALLOW,
                reason="allowed",
            ),
            ObservationPlanItem(
                id="js",
                target="https://www.example.com/_next/static/chunks/app.js",
                status=PlanItemStatus.AUTHORIZABLE,
                authorization_decision=Decision.ALLOW,
                reason="allowed",
            ),
            ObservationPlanItem(
                id="blocked",
                target="https://www.example.com/admin",
                status=PlanItemStatus.BLOCKED_POLICY,
                authorization_decision=Decision.DENY,
                reason="blocked",
            ),
        ],
    )


def test_priority_queue_selects_highest_priority_authorizable_only() -> None:
    queue = build_priority_work_queue(
        _plan(),
        {
            "https://www.example.com/": 76,
            "https://www.example.com/_next/static/chunks/app.js": 91,
            "https://www.example.com/admin": 999,
        },
        max_items=1,
    )
    assert len(queue.items) == 1
    assert queue.items[0].target.endswith("app.js")
    assert queue.items[0].requires_new_permit is True


def test_priority_never_promotes_blocked_item() -> None:
    queue = build_priority_work_queue(_plan(), {"https://www.example.com/admin": 999}, max_items=10)
    assert all(item.target != "https://www.example.com/admin" for item in queue.items)


def test_static_js_analysis_is_offline_and_nonconfirmatory(tmp_path: Path) -> None:
    artifact = tmp_path / "app.js"
    artifact.write_text(
        'const api="/api/profile"; const route="/account"; //# sourceMappingURL=app.js.map',
        encoding="utf-8",
    )
    result = analyze_javascript_file(artifact)
    assert result.network_performed is False
    assert result.artifact_sha256
    assert result.signals
    assert all(signal.vulnerability_confirmed is False for signal in result.signals)
