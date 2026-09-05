from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_bundle import RuntimeBundleManifest


class RuntimeReadinessProjection(BaseModel):
    model_config = ConfigDict(frozen=True)

    bundle_defined: bool
    immutable_artifacts_ready: bool
    browser_runtime_ready: bool
    external_tool_runtime_ready: bool
    field_qualification_complete: bool
    blockers: tuple[str, ...] = Field(default_factory=tuple)


def project_runtime_readiness(bundle: RuntimeBundleManifest) -> RuntimeReadinessProjection:
    pinned = all(item.digest_is_pinned for item in bundle.artifacts)
    blockers: list[str] = []
    if not pinned:
        blockers.append("worker OCI artifacts must be built and digest-pinned")
    if not bundle.field_tested:
        blockers.append("isolated worker bundle is not field-tested")
    if not bundle.qualification_evidence_ids:
        blockers.append("runtime qualification evidence is not recorded")
    ready = bundle.operational_ready
    return RuntimeReadinessProjection(
        bundle_defined=True,
        immutable_artifacts_ready=pinned,
        browser_runtime_ready=ready,
        external_tool_runtime_ready=ready,
        field_qualification_complete=ready,
        blockers=tuple(blockers),
    )
