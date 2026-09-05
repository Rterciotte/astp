from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from astp.auth_session import AuthSessionProfile, assert_session_target_allowed
from astp.authenticated_transport import AuthenticatedObservationTransport
from astp.evidence_store import SensitivityLabel
from astp.models import Engagement, TestDefinition
from astp.observation import ObservationResult, observe_http
from astp.permits import SignedExecutionPermit
from astp.secret_runtime import resolve_secret_reference
from astp.transport import ObservationTransport, PinnedObservationTransport


def observe_authenticated_http(
    permit: SignedExecutionPermit,
    engagement: Engagement,
    test: TestDefinition,
    keys: str | bytes | Mapping[str, str | bytes],
    session: AuthSessionProfile,
    *,
    target: str,
    method: str,
    requested_rps: float | None,
    state_path: Path,
    audit_path: Path,
    evidence_path: Path,
    manifest_path: Path,
    rate_state_path: Path,
    runtime_db_path: Path | None = None,
    transport: ObservationTransport | None = None,
) -> ObservationResult:
    assert_session_target_allowed(session, target)
    wrapped = AuthenticatedObservationTransport(
        transport or PinnedObservationTransport(),
        session,
        resolve_secret_reference,
    )
    return observe_http(
        permit,
        engagement,
        test,
        keys,
        target=target,
        method=method,
        identity=session.identity,
        requested_rps=requested_rps,
        state_path=state_path,
        audit_path=audit_path,
        evidence_path=evidence_path,
        manifest_path=manifest_path,
        rate_state_path=rate_state_path,
        runtime_db_path=runtime_db_path,
        sensitivity=SensitivityLabel.RESTRICTED,
        transport=wrapped,
    )
