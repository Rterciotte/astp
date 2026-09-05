from __future__ import annotations

from collections import defaultdict, deque

from pydantic import BaseModel, Field

from astp.worker_job import WorkerJobEnvelope


class CapabilitySchedule(BaseModel):
    schema_version: str = "1"
    job_ids: list[str] = Field(default_factory=list)
    network_performed: bool = False


def round_robin_capabilities(jobs: list[WorkerJobEnvelope]) -> CapabilitySchedule:
    buckets: dict[str, deque[WorkerJobEnvelope]] = defaultdict(deque)
    for job in sorted(jobs, key=lambda item: (item.capability_id, item.id)):
        buckets[job.capability_id].append(job)
    order: list[str] = []
    keys = sorted(buckets)
    while any(buckets.values()):
        for key in keys:
            if buckets[key]:
                order.append(buckets[key].popleft().id)
    return CapabilitySchedule(job_ids=order)
