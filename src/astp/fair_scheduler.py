from __future__ import annotations

from collections import deque

from pydantic import BaseModel, Field

from astp.work_queue import WorkQueueItem


class ProgramQueue(BaseModel):
    engagement_id: str
    items: list[WorkQueueItem] = Field(default_factory=list)


def schedule_fair_sessions(
    queues: list[ProgramQueue], *, max_items: int = 100
) -> list[WorkQueueItem]:
    if max_items < 1:
        raise ValueError("max_items must be positive")
    active = deque((queue.engagement_id, deque(queue.items)) for queue in queues if queue.items)
    output: list[WorkQueueItem] = []
    while active and len(output) < max_items:
        engagement_id, items = active.popleft()
        output.append(items.popleft())
        if items:
            active.append((engagement_id, items))
    return output
