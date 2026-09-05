from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from astp.runtime_artifacts import RuntimeArtifact, RuntimeArtifactKind


class RuntimeBundleManifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    artifacts: tuple[RuntimeArtifact, ...]
    read_only_rootfs: bool = True
    no_new_privileges: bool = True
    drop_all_capabilities: bool = True
    isolated_network_default: bool = True
    field_tested: bool = False
    qualification_evidence_ids: tuple[str, ...] = Field(default_factory=tuple)

    @property
    def operational_ready(self) -> bool:
        return (
            self.field_tested
            and bool(self.qualification_evidence_ids)
            and all(item.digest_is_pinned for item in self.artifacts)
            and self.read_only_rootfs
            and self.no_new_privileges
            and self.drop_all_capabilities
            and self.isolated_network_default
        )


def planned_runtime_bundle() -> RuntimeBundleManifest:
    # Digests are intentionally placeholders until images are actually built and recorded.
    return RuntimeBundleManifest(
        id="astp.isolated-workers.v1",
        artifacts=(
            RuntimeArtifact(
                runtime_id="playwright.isolated.v1",
                kind=RuntimeArtifactKind.OCI_IMAGE,
                reference="astp/playwright-worker",
                digest="unbuilt",
                version="planned",
                capabilities=("browser.observation.v1",),
            ),
            RuntimeArtifact(
                runtime_id="security-tools.isolated.v1",
                kind=RuntimeArtifactKind.OCI_IMAGE,
                reference="astp/security-tools-worker",
                digest="unbuilt",
                version="planned",
                capabilities=(
                    "external.nmap.discovery.v1",
                    "external.nuclei.safe.v1",
                    "external.zap.baseline.v1",
                ),
            ),
        ),
    )
