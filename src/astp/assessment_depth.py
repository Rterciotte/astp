from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from astp.verifier_catalog import builtin_verifier_catalog
from astp.worker_runtime_manifest import builtin_worker_runtime_manifests


class AssessmentDepthStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    verifier_definitions: int
    worker_runtime_manifests: int
    operational_worker_runtimes: int
    broad_active_verification_ready: bool
    full_runtime_ready: bool


def current_assessment_depth() -> AssessmentDepthStatus:
    runtimes = builtin_worker_runtime_manifests()
    return AssessmentDepthStatus(
        verifier_definitions=len(builtin_verifier_catalog()),
        worker_runtime_manifests=len(runtimes),
        operational_worker_runtimes=sum(1 for item in runtimes if item.operational_ready),
        broad_active_verification_ready=False,
        full_runtime_ready=all(item.operational_ready for item in runtimes),
    )
