from __future__ import annotations

import hashlib
import http.client
import os
import posixpath
import sqlite3
import threading
import time
from datetime import UTC, datetime
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar, Self
from urllib.parse import unquote, urljoin, urlsplit

from astp.detector_run_permit import SignedDetectorRunPermit

SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
HOP_HEADERS = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"}
PROVENANCE_HEADER = "X-ASTP-Response-Provenance"
SYNTHETIC_HEADER = "X-ASTP-Response-Synthetic"
BOUNDARY_REASON_HEADER = "X-ASTP-Boundary-Reason"


class AcceptanceProxyFault(StrEnum):
    AFTER_WORKER_LAUNCH_BEFORE_FIRST_IO = "after_worker_launch_before_first_io"
    AFTER_FIRST_PROXY_FORWARD = "after_first_proxy_forward"
    HOLD_AFTER_TARGET_RESPONSE = "hold_after_target_response"


class ProxyAccounting:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                """CREATE TABLE IF NOT EXISTS requests(
                request_id TEXT PRIMARY KEY, detector_run_id TEXT NOT NULL,
                permit_id TEXT NOT NULL, method TEXT NOT NULL, target TEXT NOT NULL,
                state TEXT NOT NULL, request_bytes INTEGER NOT NULL DEFAULT 0,
                response_bytes INTEGER NOT NULL DEFAULT 0, status INTEGER,
                started_at TEXT NOT NULL, finished_at TEXT, detail TEXT NOT NULL DEFAULT '')"""
            )

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def count(self, states: tuple[str, ...]) -> int:
        marks = ",".join("?" for _ in states)
        with self.connect() as db:
            return int(
                db.execute(
                    f"SELECT count(*) FROM requests WHERE state IN ({marks})", states
                ).fetchone()[0]
            )

    def start(
        self,
        request_id: str,
        permit_id: str,
        run_id: str,
        method: str,
        target: str,
        state: str,
        detail: str = "",
    ) -> None:
        with self.lock, self.connect() as db:
            db.execute(
                "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    run_id,
                    permit_id,
                    method,
                    target,
                    state,
                    0,
                    0,
                    None,
                    datetime.now(UTC).isoformat(),
                    None,
                    detail,
                ),
            )

    def finish(
        self,
        request_id: str,
        state: str,
        status: int | None,
        request_bytes: int,
        response_bytes: int,
        detail: str = "",
    ) -> None:
        with self.lock, self.connect() as db:
            db.execute(
                "UPDATE requests SET state=?,status=?,request_bytes=?,response_bytes=?,finished_at=?,detail=? WHERE request_id=?",
                (
                    state,
                    status,
                    request_bytes,
                    response_bytes,
                    datetime.now(UTC).isoformat(),
                    detail,
                    request_id,
                ),
            )

    def summary(self) -> dict[str, int]:
        with self.connect() as db:
            rows = dict(db.execute("SELECT state,count(*) FROM requests GROUP BY state"))
            byte_row = db.execute(
                "SELECT COALESCE(sum(request_bytes),0),COALESCE(sum(response_bytes),0) FROM requests"
            ).fetchone()
        return {
            "requests_attempted": sum(rows.values()),
            "requests_forwarded": (
                rows.get("forwarding", 0)
                + rows.get("response_received", 0)
                + rows.get("failed_after_io", 0)
            ),
            "responses_received": rows.get("response_received", 0),
            "requests_blocked_before_io": rows.get("blocked_before_io", 0),
            "requests_failed_after_io": rows.get("failed_after_io", 0),
            "unknown_outcomes": rows.get("forwarding", 0),
            "request_bytes": int(byte_row[0]),
            "response_bytes": int(byte_row[1]),
        }


class CountingProxy:
    def __init__(
        self,
        permit: SignedDetectorRunPermit,
        signing_key: str | bytes,
        ledger_path: Path,
        *,
        expected_campaign_id: str | None = None,
        expected_program_id: str | None = None,
        expected_detector_id: str | None = None,
        acceptance_fault: AcceptanceProxyFault | None = None,
    ):
        self._signing_key = signing_key
        self.permit = permit.verify(signing_key)
        for field, expected in {
            "campaign_id": expected_campaign_id,
            "program_id": expected_program_id,
            "detector_id": expected_detector_id,
        }.items():
            if expected is not None and getattr(self.permit.payload, field) != expected:
                raise ValueError(f"detector-run permit {field} binding mismatch")
        self.accounting = ProxyAccounting(ledger_path)
        self.lock = threading.Lock()
        self.active = 0
        self.sequence = self.accounting.count(
            ("forwarding", "response_received", "failed_after_io", "blocked_before_io")
        )
        self.last_forwarded = 0.0
        self.circuit_failures = 0
        self.acceptance_fault = acceptance_fault

    def _request_id(self) -> str:
        with self.lock:
            self.sequence += 1
            value = f"{self.permit.payload.detector_run_id}:{self.sequence}"
        return hashlib.sha256(value.encode()).hexdigest()[:24]

    def authorize(self, method: str, target: str) -> tuple[str, str | None]:
        request_id = self._request_id()
        try:
            self.permit.verify(self._signing_key)
        except (ValueError, AttributeError) as exc:
            return request_id, str(exc)
        parsed = urlsplit(target)
        origin = f"{parsed.scheme}://{parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
        allowed = urlsplit(self.permit.payload.allowed_origin)
        allowed_origin = f"{allowed.scheme}://{allowed.hostname}:{allowed.port or (443 if allowed.scheme == 'https' else 80)}"
        if parsed.scheme not in {"http", "https"} or origin != allowed_origin:
            return request_id, "origin/scheme/port rejected"
        decoded_path = unquote(parsed.path)
        normalized_path = posixpath.normpath(decoded_path)
        if decoded_path.endswith("/") and normalized_path != "/":
            normalized_path += "/"
        allowed_path = (
            posixpath.normpath(unquote(self.permit.payload.allowed_path_prefix)).rstrip("/") or "/"
        )
        path_allowed = (
            allowed_path == "/"
            or normalized_path == allowed_path
            or normalized_path.startswith(allowed_path + "/")
        )
        if not path_allowed:
            return request_id, "path outside authorized prefix"
        if method.upper() not in self.permit.payload.allowed_methods:
            return request_id, "method rejected"
        if (
            self.accounting.count(("forwarding", "response_received", "failed_after_io"))
            >= self.permit.payload.max_requests
        ):
            return request_id, "request budget exhausted"
        with self.lock:
            if self.active >= self.permit.payload.max_concurrency:
                return request_id, "concurrency ceiling exceeded"
            if self.circuit_failures >= 3:
                return request_id, "circuit breaker open"
            self.active += 1
        return request_id, None

    def forward(
        self, method: str, target: str, headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, str], bytes, str]:
        if self.acceptance_fault is AcceptanceProxyFault.AFTER_WORKER_LAUNCH_BEFORE_FIRST_IO:
            os._exit(86)
        request_id, denial = self.authorize(method, target)
        payload = self.permit.payload
        if denial:
            self.accounting.start(
                request_id,
                payload.permit_id,
                payload.detector_run_id,
                method,
                target,
                "blocked_before_io",
                denial,
            )
            return (
                429 if "budget" in denial or "concurrency" in denial else 403,
                {
                    PROVENANCE_HEADER: "astp_boundary",
                    SYNTHETIC_HEADER: "true",
                    BOUNDARY_REASON_HEADER: denial.replace(" ", "_"),
                },
                denial.encode(),
                request_id,
            )
        try:
            interval = 1.0 / payload.max_rps
            with self.lock:
                delay = max(0.0, self.last_forwarded + interval - time.monotonic())
            if delay:
                time.sleep(delay)
            self.accounting.start(
                request_id,
                payload.permit_id,
                payload.detector_run_id,
                method,
                target,
                "forwarding",
            )
            if self.acceptance_fault is AcceptanceProxyFault.AFTER_FIRST_PROXY_FORWARD:
                os._exit(86)
            with self.lock:
                self.last_forwarded = time.monotonic()
            parsed = urlsplit(target)
            clean_headers = {
                name: value
                for name, value in headers.items()
                if name.lower() not in HOP_HEADERS | SECRET_HEADERS | {"host"}
            }
            clean_headers["Host"] = parsed.netloc
            connection_class = (
                http.client.HTTPSConnection
                if parsed.scheme == "https"
                else http.client.HTTPConnection
            )
            connection = connection_class(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                timeout=10,
            )
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request(method, path, body=body or None, headers=clean_headers)
            response = connection.getresponse()
            response_body = response.read(1_048_576)
            response_headers = dict(response.getheaders())
            if self.acceptance_fault is AcceptanceProxyFault.HOLD_AFTER_TARGET_RESPONSE:
                time.sleep(300)
            response_headers[PROVENANCE_HEADER] = "target"
            response_headers[SYNTHETIC_HEADER] = "false"
            with self.lock:
                self.circuit_failures = 0
            if 300 <= response.status < 400 and response_headers.get("Location"):
                redirect = urljoin(target, response_headers["Location"])
                redirect_origin = urlsplit(redirect)
                allowed = urlsplit(payload.allowed_origin)
                if (
                    redirect_origin.scheme,
                    redirect_origin.hostname,
                    redirect_origin.port or (443 if redirect_origin.scheme == "https" else 80),
                ) != (
                    allowed.scheme,
                    allowed.hostname,
                    allowed.port or (443 if allowed.scheme == "https" else 80),
                ):
                    self.accounting.finish(
                        request_id,
                        "response_received",
                        response.status,
                        len(body),
                        len(response_body),
                        "out-of-scope redirect blocked",
                    )
                    response_headers["X-ASTP-Redirect-Target"] = redirect
                    response_headers[BOUNDARY_REASON_HEADER] = "out_of_scope_redirect"
                    return response.status, response_headers, response_body, request_id
            retry_after = response_headers.get("Retry-After", "")
            retry_detail = (
                f"retry_after_seconds={retry_after}"
                if response.status == 429 and retry_after.isdigit()
                else ""
            )
            self.accounting.finish(
                request_id,
                "response_received",
                response.status,
                len(body),
                len(response_body),
                retry_detail,
            )
            return response.status, response_headers, response_body, request_id
        except OSError as exc:
            with self.lock:
                self.circuit_failures += 1
            self.accounting.finish(
                request_id, "failed_after_io", None, len(body), 0, type(exc).__name__
            )
            return (
                502,
                {
                    PROVENANCE_HEADER: "astp_boundary",
                    SYNTHETIC_HEADER: "true",
                    BOUNDARY_REASON_HEADER: "upstream_failure",
                },
                b"upstream failure",
                request_id,
            )
        finally:
            with self.lock:
                self.active -= 1


class ProxyHandler(BaseHTTPRequestHandler):
    proxy: ClassVar[CountingProxy]

    def log_message(self, *_args: object) -> None:
        return

    def do_CONNECT(self) -> None:
        self.send_error(405, "CONNECT is not enabled")

    def do_GET(self) -> None:
        self._forward()

    def do_HEAD(self) -> None:
        self._forward()

    def _forward(self) -> None:
        length = min(int(self.headers.get("Content-Length", "0")), 1_048_576)
        body = self.rfile.read(length) if length else b""
        status, headers, response, request_id = self.proxy.forward(
            self.command, self.path, dict(self.headers), body
        )
        # Avoid BaseHTTPRequestHandler's synthetic Server/Date headers. All
        # forwarded headers must retain their actual producer provenance.
        self.send_response_only(status)
        for name, value in headers.items():
            if name.lower() not in HOP_HEADERS | {"content-length"}:
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(response)))
        self.send_header("X-ASTP-Request-ID", request_id)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response)


class RunningCountingProxy:
    def __init__(self, proxy: CountingProxy):
        ProxyHandler.proxy = proxy
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def main() -> None:
    permit_path = Path(os.environ.get("ASTP_DETECTOR_RUN_PERMIT", "/run/astp/permit.json"))
    ledger_path = Path(os.environ.get("ASTP_PROXY_LEDGER", "/var/lib/astp/proxy-ledger.db"))
    signing_key = os.environ.get("ASTP_DETECTOR_RUN_KEY", "")
    if len(signing_key.encode()) < 32:
        raise SystemExit("detector-run signing key must contain at least 32 bytes")
    permit = SignedDetectorRunPermit.model_validate_json(permit_path.read_text(encoding="utf-8"))
    fault_value = os.environ.get("ASTP_ACCEPTANCE_PROXY_FAULT")
    fault = None
    if fault_value:
        if os.environ.get("ASTP_ACCEPTANCE_MODE") != "local-only":
            raise SystemExit("proxy fault injection requires local-only acceptance mode")
        if urlsplit(permit.payload.allowed_origin).hostname != "astp-m52-lab":
            raise SystemExit("proxy fault injection is restricted to the synthetic local lab")
        fault = AcceptanceProxyFault(fault_value)
    proxy = CountingProxy(permit, signing_key, ledger_path, acceptance_fault=fault)
    ProxyHandler.proxy = proxy
    ThreadingHTTPServer(("0.0.0.0", 8081), ProxyHandler).serve_forever()


if __name__ == "__main__":
    main()
