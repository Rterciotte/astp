from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from astp.external_adapter_runtime import ExternalAdapterReceipt


class AdapterEvidenceSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    adapter_id: str
    job_id: str
    successful: bool
    stdout_sha256: str
    stderr_sha256: str
    finding_confirmed: bool = False


def summarize_adapter_receipt(receipt: ExternalAdapterReceipt) -> AdapterEvidenceSummary:
    return AdapterEvidenceSummary(
        adapter_id=receipt.adapter_id,
        job_id=receipt.job_id,
        successful=receipt.exit_code == 0,
        stdout_sha256=receipt.stdout_sha256,
        stderr_sha256=receipt.stderr_sha256,
    )
