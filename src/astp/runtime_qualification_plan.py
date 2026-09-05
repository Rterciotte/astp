from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from astp.runtime_bundle import RuntimeBundleManifest


class QualificationStep(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    description: str
    requires_network: bool = False


class RuntimeQualificationPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    bundle_id: str
    steps: tuple[QualificationStep, ...]
    target_network_execution_enabled: bool = False


def build_runtime_qualification_plan(bundle: RuntimeBundleManifest) -> RuntimeQualificationPlan:
    return RuntimeQualificationPlan(
        bundle_id=bundle.id,
        steps=(
            QualificationStep(id="artifact-digest", description="record immutable OCI digest"),
            QualificationStep(id="health", description="run no-network runtime health probe"),
            QualificationStep(
                id="no-shell", description="verify arbitrary shell execution is rejected"
            ),
            QualificationStep(id="no-keys", description="verify signing keys are not mounted"),
            QualificationStep(
                id="output-bound", description="verify oversized worker output is truncated"
            ),
            QualificationStep(
                id="permit-order", description="verify permit is consumed before target I/O"
            ),
            QualificationStep(
                id="network-deny",
                description="verify target network I/O is rejected without a permit",
                requires_network=True,
            ),
            QualificationStep(
                id="authorized-field-test",
                description="record an authorized runtime field test",
                requires_network=True,
            ),
        ),
    )
