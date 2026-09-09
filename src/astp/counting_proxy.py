from __future__ import annotations

import hashlib
import http.client
import os
import sqlite3
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar, Self
from urllib.parse import urljoin, urlsplit

from astp.detector_run_permit import SignedDetectorRunPermit

SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
HOP_HEADERS = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade"}


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
            "requests_forwarded": rows.get("response_received", 0) + rows.get("failed_after_io", 0),
            "responses_received": rows.get("response_received", 0),
            "requests_blocked_before_io": rows.get("blocked_before_io", 0),
            "requests_failed_after_io": rows.get("failed_after_io", 0),
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
        if parsed.scheme != "http" or origin != allowed_origin:
            return request_id, "origin/scheme/port rejected"
        if not parsed.path.startswith(self.permit.payload.allowed_path_prefix):
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
                {},
                denial.encode(),
                request_id,
            )
        self.accounting.start(
            request_id, payload.permit_id, payload.detector_run_id, method, target, "forwarding"
        )
        try:
            interval = 1.0 / payload.max_rps
            with self.lock:
                delay = max(0.0, self.last_forwarded + interval - time.monotonic())
            if delay:
                time.sleep(delay)
            parsed = urlsplit(target)
            clean_headers = {
                name: value
                for name, value in headers.items()
                if name.lower() not in HOP_HEADERS | SECRET_HEADERS
            }
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request(method, path, body=body or None, headers=clean_headers)
            response = connection.getresponse()
            response_body = response.read(1_048_576)
            response_headers = dict(response.getheaders())
            with self.lock:
                self.last_forwarded = time.monotonic()
                self.circuit_failures = 0
            if 300 <= response.status < 400 and response_headers.get("Location"):
                redirect = urljoin(target, response_headers["Location"])
                redirect_origin = urlsplit(redirect)
                allowed = urlsplit(payload.allowed_origin)
                if (
                    redirect_origin.scheme,
                    redirect_origin.hostname,
                    redirect_origin.port or 80,
                ) != (allowed.scheme, allowed.hostname, allowed.port or 80):
                    self.accounting.finish(
                        request_id,
                        "response_received",
                        response.status,
                        len(body),
                        len(response_body),
                        "out-of-scope redirect blocked",
                    )
                    return 403, {}, b"out-of-scope redirect blocked", request_id
            self.accounting.finish(
                request_id, "response_received", response.status, len(body), len(response_body)
            )
            return response.status, response_headers, response_body, request_id
        except OSError as exc:
            with self.lock:
                self.circuit_failures += 1
            self.accounting.finish(
                request_id, "failed_after_io", None, len(body), 0, type(exc).__name__
            )
            return 502, {}, b"upstream failure", request_id
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
        self.send_response(status)
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
    proxy = CountingProxy(permit, signing_key, ledger_path)
    ProxyHandler.proxy = proxy
    ThreadingHTTPServer(("0.0.0.0", 8081), ProxyHandler).serve_forever()


if __name__ == "__main__":
    main()
