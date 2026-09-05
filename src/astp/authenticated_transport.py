from __future__ import annotations

from collections.abc import Callable
from urllib.request import Request

from astp.auth_session import AuthInjection, AuthSessionProfile, assert_session_target_allowed
from astp.secret_runtime import ResolvedSecret
from astp.transport import ObservationTransport, TransportResponse

SecretResolver = Callable[[object], ResolvedSecret]


class AuthenticatedObservationTransport:
    """Inject origin-bound credentials only at the transport boundary."""

    def __init__(
        self,
        base: ObservationTransport,
        session: AuthSessionProfile,
        resolver: SecretResolver,
    ) -> None:
        self._base = base
        self._session = session
        self._resolver = resolver

    def open(self, request: Request, *, timeout: float) -> TransportResponse:
        assert_session_target_allowed(self._session, request.full_url)
        copied = Request(
            request.full_url,
            method=request.get_method(),
            headers={name: value for name, value in request.header_items()},
        )
        for binding in self._session.bindings:
            resolved = self._resolver(binding.secret)
            if binding.injection == AuthInjection.BEARER:
                copied.add_header("Authorization", f"Bearer {resolved.value}")
            elif binding.injection == AuthInjection.COOKIE:
                copied.add_header("Cookie", resolved.value)
            else:
                copied.add_header(binding.header_name or "X-ASTP-Auth", resolved.value)
        return self._base.open(copied, timeout=timeout)
