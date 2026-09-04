from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.parse import urlsplit
from urllib.request import Request


class TransportFailureKind(str, Enum):
    DNS = "dns"
    TLS = "tls"
    TIMEOUT = "timeout"
    CONNECTION = "connection"
    IO = "io"


@dataclass(frozen=True)
class ResolvedEndpoint:
    hostname: str
    port: int
    addresses: tuple[str, ...]
    connected_address: str | None = None
    tls_protocol: str | None = None
    tls_cipher: str | None = None
    peer_certificate_sha256: str | None = None


@dataclass
class TransportResponse:
    response: object
    resolved_endpoint: ResolvedEndpoint


class ObservationTransportError(RuntimeError):
    def __init__(self, kind: TransportFailureKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class ObservationTransport(Protocol):
    def open(self, request: Request, *, timeout: float) -> TransportResponse: ...


def resolve_endpoint(hostname: str, port: int) -> ResolvedEndpoint:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ObservationTransportError(TransportFailureKind.DNS, "DNS resolution failed.") from exc
    addresses = tuple(sorted({item[4][0] for item in infos}))
    if not addresses:
        raise ObservationTransportError(TransportFailureKind.DNS, "DNS returned no addresses.")
    return ResolvedEndpoint(hostname=hostname, port=port, addresses=addresses)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(
        self,
        hostname: str,
        port: int,
        address: str,
        *,
        timeout: float,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._address, self.port),
            self.timeout,
            self.source_address,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        port: int,
        address: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._address = address

    def connect(self) -> None:
        raw_socket = socket.create_connection(
            (self._address, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


class PinnedObservationTransport:
    """Resolve once, then connect only to one of those exact resolved addresses."""

    def __init__(self, *, ssl_context: ssl.SSLContext | None = None) -> None:
        self._ssl_context = ssl_context or ssl.create_default_context()

    @staticmethod
    def _request_path(request: Request) -> str:
        parsed = urlsplit(request.full_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return path

    @staticmethod
    def _headers(request: Request, hostname: str, port: int, scheme: str) -> dict[str, str]:
        headers = {name: value for name, value in request.header_items()}
        default_port = 443 if scheme == "https" else 80
        host_header = hostname if port == default_port else f"{hostname}:{port}"
        headers["Host"] = host_header
        return headers

    def _connection(
        self,
        scheme: str,
        hostname: str,
        port: int,
        address: str,
        timeout: float,
    ) -> http.client.HTTPConnection:
        if scheme == "https":
            return _PinnedHTTPSConnection(
                hostname,
                port,
                address,
                timeout=timeout,
                context=self._ssl_context,
            )
        return _PinnedHTTPConnection(hostname, port, address, timeout=timeout)

    def open(self, request: Request, *, timeout: float) -> TransportResponse:
        parsed = urlsplit(request.full_url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        resolved = resolve_endpoint(hostname, port)
        path = self._request_path(request)
        headers = self._headers(request, hostname, port, scheme)
        last_error: BaseException | None = None

        for address in resolved.addresses:
            connection = self._connection(scheme, hostname, port, address, timeout)
            try:
                connection.request(request.get_method(), path, headers=headers)
                response = connection.getresponse()
                tls_protocol = None
                tls_cipher = None
                certificate_hash = None
                sock = connection.sock
                if isinstance(sock, ssl.SSLSocket):
                    tls_protocol = sock.version()
                    cipher = sock.cipher()
                    tls_cipher = cipher[0] if cipher else None
                    certificate = sock.getpeercert(binary_form=True)
                    if certificate:
                        certificate_hash = hashlib.sha256(certificate).hexdigest()
                endpoint = ResolvedEndpoint(
                    hostname=hostname,
                    port=port,
                    addresses=resolved.addresses,
                    connected_address=address,
                    tls_protocol=tls_protocol,
                    tls_cipher=tls_cipher,
                    peer_certificate_sha256=certificate_hash,
                )
                return TransportResponse(response=response, resolved_endpoint=endpoint)
            except ssl.SSLError as exc:
                connection.close()
                raise ObservationTransportError(TransportFailureKind.TLS, "TLS failed.") from exc
            except TimeoutError as exc:
                connection.close()
                last_error = exc
            except (ConnectionError, OSError, http.client.HTTPException) as exc:
                connection.close()
                last_error = exc

        if isinstance(last_error, (TimeoutError, socket.timeout)):
            raise ObservationTransportError(
                TransportFailureKind.TIMEOUT, "Request timed out."
            ) from last_error
        if isinstance(last_error, http.client.HTTPException):
            raise ObservationTransportError(
                TransportFailureKind.IO, "HTTP transport failed."
            ) from last_error
        raise ObservationTransportError(
            TransportFailureKind.CONNECTION, "Connection failed."
        ) from last_error


# Backward-compatible name for callers/tests from Milestone 2.2.
UrllibObservationTransport = PinnedObservationTransport
