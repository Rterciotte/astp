from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from enum import Enum
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


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


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def resolve_endpoint(hostname: str, port: int) -> ResolvedEndpoint:
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ObservationTransportError(TransportFailureKind.DNS, "DNS resolution failed.") from exc
    addresses = tuple(sorted({item[4][0] for item in infos}))
    if not addresses:
        raise ObservationTransportError(TransportFailureKind.DNS, "DNS returned no addresses.")
    return ResolvedEndpoint(hostname=hostname, port=port, addresses=addresses)


class UrllibObservationTransport:
    def open(self, request: Request, *, timeout: float) -> TransportResponse:
        parsed = urlsplit(request.full_url)
        host = parsed.hostname or ""
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        resolved = resolve_endpoint(host, port)
        opener = build_opener(_NoRedirectHandler())
        try:
            try:
                response = opener.open(request, timeout=timeout)
            except HTTPError as exc:
                response = exc
        except ssl.SSLError as exc:
            raise ObservationTransportError(TransportFailureKind.TLS, "TLS failed.") from exc
        except TimeoutError as exc:
            raise ObservationTransportError(
                TransportFailureKind.TIMEOUT, "Request timed out."
            ) from exc
        except URLError as exc:
            reason = exc.reason
            if isinstance(reason, ssl.SSLError):
                kind = TransportFailureKind.TLS
            elif isinstance(reason, (TimeoutError, socket.timeout)):
                kind = TransportFailureKind.TIMEOUT
            else:
                kind = TransportFailureKind.CONNECTION
            raise ObservationTransportError(kind, "Connection failed.") from exc
        except OSError as exc:
            raise ObservationTransportError(
                TransportFailureKind.IO, "Transport I/O failed."
            ) from exc
        return TransportResponse(response=response, resolved_endpoint=resolved)
