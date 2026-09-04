from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from astp.models import Engagement, TestDefinition
from astp.permits import PermitVerificationRequest, SignedExecutionPermit
from astp.runtime_state import WorkerAdmissionResult
from astp.transport import ObservationTransport


class WorkerCapability(BaseModel):
    model_config = ConfigDict(frozen=True)

    capability_id: str
    supported_schemes: tuple[str, ...]
    supported_methods: tuple[str, ...]
    follows_redirects: bool = False
    state_changing: bool = False
    max_timeout_seconds: float = Field(gt=0)
    max_body_bytes: int = Field(ge=0)


HTTP_OBSERVATION_CAPABILITY = WorkerCapability(
    capability_id="http.observation.v1",
    supported_schemes=("http", "https"),
    supported_methods=("GET", "HEAD"),
    follows_redirects=False,
    state_changing=False,
    max_timeout_seconds=30.0,
    max_body_bytes=1_048_576,
)


def ensure_capability_compatible(
    capability: WorkerCapability,
    permit: SignedExecutionPermit,
    *,
    target: str,
    method: str,
    timeout_seconds: float,
    max_body_bytes: int,
) -> None:
    scheme = urlsplit(target).scheme.lower()
    normalized_method = method.upper()
    if scheme not in capability.supported_schemes:
        raise ValueError(f"Worker capability does not support URL scheme {scheme!r}.")
    if normalized_method not in capability.supported_methods:
        raise ValueError(f"Worker capability does not support HTTP method {normalized_method!r}.")
    if permit.payload.http_method != normalized_method:
        raise ValueError("Execution permit method does not match worker action.")
    if timeout_seconds > capability.max_timeout_seconds:
        raise ValueError("Requested timeout exceeds worker capability.")
    if max_body_bytes > capability.max_body_bytes:
        raise ValueError("Requested body capture exceeds worker capability.")
    if capability.state_changing:
        raise ValueError("Observation worker capability must remain non-state-changing.")


@runtime_checkable
class WorkerAdmissionStore(Protocol):
    def admit(
        self,
        permit: SignedExecutionPermit,
        engagement: Engagement,
        test: TestDefinition,
        request: PermitVerificationRequest,
        *,
        action_key: str,
        max_requests_per_second: float,
    ) -> WorkerAdmissionResult: ...


@runtime_checkable
class EvidenceRegistrar(Protocol):
    def register(
        self,
        artifact_path: Path,
        *,
        evidence_type: str,
        evidence_id: str,
        permit_id: str,
        action_id: str,
    ) -> object: ...


@runtime_checkable
class ObservationWorkerDependencies(Protocol):
    @property
    def transport(self) -> ObservationTransport: ...

    @property
    def admission_store(self) -> WorkerAdmissionStore: ...

    @property
    def evidence_registrar(self) -> EvidenceRegistrar: ...
