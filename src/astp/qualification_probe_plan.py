from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from astp.qualification_session import QualificationProbe


class ProbeStep(BaseModel):
    model_config = ConfigDict(frozen=True)
    probe: QualificationProbe
    expected: str
    requires_network: bool = False


def physical_probe_plan() -> tuple[ProbeStep, ...]:
    return (
        ProbeStep(
            probe=QualificationProbe.IMAGE_DIGEST, expected="immutable sha256 image digest recorded"
        ),
        ProbeStep(
            probe=QualificationProbe.READ_ONLY_ROOT, expected="write outside tmpfs is rejected"
        ),
        ProbeStep(probe=QualificationProbe.NO_NEW_PRIVILEGES, expected="no-new-privileges is set"),
        ProbeStep(
            probe=QualificationProbe.SHELL_REJECTED, expected="arbitrary shell request is rejected"
        ),
        ProbeStep(
            probe=QualificationProbe.SIGNING_KEYS_ABSENT, expected="permit signing keys are absent"
        ),
        ProbeStep(
            probe=QualificationProbe.NETWORK_WITHOUT_PERMIT_REJECTED,
            expected="network attempt without consumed permit is rejected",
            requires_network=True,
        ),
        ProbeStep(
            probe=QualificationProbe.PERMIT_BEFORE_IO,
            expected="receipt proves permit precedes I/O",
            requires_network=True,
        ),
        ProbeStep(
            probe=QualificationProbe.BOUNDED_OUTPUT, expected="worker output obeys configured bound"
        ),
        ProbeStep(
            probe=QualificationProbe.RECEIPT_INGESTION,
            expected="receipt is accepted by evidence bridge",
        ),
    )
