from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from astp.planner import ObservationPlan, PlanItemStatus
from astp.work_queue import WorkQueue, WorkQueueItem


def load_priority_scores(path: Path) -> dict[str, int]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    scores: dict[str, int] = {}
    for row in raw.get("targets", []):
        if (
            isinstance(row, dict)
            and isinstance(row.get("target"), str)
            and isinstance(row.get("score"), int)
        ):
            scores[row["target"]] = row["score"]
    return scores


def build_priority_work_queue(
    plan: ObservationPlan,
    priority_scores: dict[str, int],
    *,
    max_items: int = 1,
) -> WorkQueue:
    """Order only already-authorizable plan items. Priority never grants authorization."""
    if max_items < 1:
        raise ValueError("max_items must be at least 1")

    rows = [item for item in plan.items if item.status == PlanItemStatus.AUTHORIZABLE]
    rows.sort(key=lambda item: (-priority_scores.get(item.target, -(10**9)), item.target, item.id))
    items = [
        WorkQueueItem(
            queue_id=f"queue-{index:04d}",
            engagement_id=plan.engagement_id,
            test_id=plan.test_id,
            plan_item_id=item.id,
            target=item.target,
            method=item.method,
            requires_new_permit=True,
        )
        for index, item in enumerate(rows[:max_items], start=1)
    ]
    return WorkQueue(
        created_at=plan.created_at,
        max_active_programs=1,
        items=items,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a priority-aware queue from a policy-evaluated plan."
    )
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--priorities", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-items", type=int, default=1)
    args = parser.parse_args()

    plan = ObservationPlan.model_validate(yaml.safe_load(args.plan.read_text(encoding="utf-8")))
    queue = build_priority_work_queue(
        plan, load_priority_scores(args.priorities), max_items=args.max_items
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        yaml.safe_dump(queue.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    print(f"Items: {len(queue.items)}")
    for item in queue.items:
        print(f"{item.queue_id}: {item.target}")
    print("Permits issued: 0")
    print("Network execution: NOT PERFORMED")
    print(f"Written to: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
