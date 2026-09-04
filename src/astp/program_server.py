from __future__ import annotations

import json
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from astp.browser_intake import BrowserCapture, write_capture
from astp.program_catalog import (
    ProgramCandidate,
    discover_programs,
    load_or_create_workspace,
    merge_discovery,
    save_workspace,
    sync_program_capture,
)

PROGRAM_INTAKE_PROTOCOL_VERSION = "2"
MAX_REQUEST_BYTES = 8_000_000


class ProgramDetailSubmission(BaseModel):
    candidate: ProgramCandidate
    capture: BrowserCapture


def _timestamp() -> str:
    return datetime.now().astimezone().strftime("%H:%M:%S")


def _log(message: str) -> None:
    print(f"[{_timestamp()}] {message}", flush=True)


class _ProgramIntakeHandler(BaseHTTPRequestHandler):
    intake_token: str
    platform: str
    latest_capture_path: Path
    catalog_path: Path
    captures_dir: Path
    programs_dir: Path

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_POST(self) -> None:
        _log(f"POST {self.path}")
        if self.headers.get("X-ASTP-Intake-Token") != self.intake_token:
            _log(f"Rejected {self.path}: invalid intake token")
            self._json_response(403, {"ok": False, "error": "invalid intake token"})
            return

        if self.path == "/v1/health":
            self._json_response(
                200,
                {
                    "ok": True,
                    "service": "astp-program-intake",
                    "protocol_version": PROGRAM_INTAKE_PROTOCOL_VERSION,
                    "platform": self.platform,
                },
            )
            _log("Browser companion health check passed")
            return

        if self.path not in {
            "/v1/browser-capture",
            "/v1/discover-programs",
            "/v1/program-detail",
        }:
            _log(f"Rejected unknown endpoint: {self.path}")
            self._json_response(404, {"ok": False, "error": "unknown intake endpoint"})
            return

        length_header = self.headers.get("Content-Length", "0")
        try:
            length = int(length_header)
        except ValueError:
            self._json_response(400, {"ok": False, "error": "invalid Content-Length"})
            return
        if length <= 0 or length > MAX_REQUEST_BYTES:
            _log(f"Rejected {self.path}: payload length {length}")
            self._json_response(413, {"ok": False, "error": "invalid intake payload size"})
            return

        try:
            raw: Any = json.loads(self.rfile.read(length).decode("utf-8"))
            if self.path == "/v1/browser-capture":
                capture = BrowserCapture.model_validate(raw)
                receipt = write_capture(capture, self.latest_capture_path)
                self._json_response(200, {"ok": True, "sha256": receipt.sha256})
                _log(f"Captured current page: {capture.url}")
                return
            if self.path == "/v1/discover-programs":
                self._discover(raw)
                return
            self._sync_detail(raw)
        except (ValueError, json.JSONDecodeError) as exc:
            _log(f"Rejected {self.path}: {exc}")
            self._json_response(400, {"ok": False, "error": str(exc)})
        except OSError as exc:
            _log(f"Storage failure during {self.path}: {exc}")
            self._json_response(500, {"ok": False, "error": "ASTP intake storage failure"})

    def _discover(self, raw: Any) -> None:
        capture = BrowserCapture.model_validate(raw)
        write_capture(capture, self.latest_capture_path)
        result = discover_programs(capture, platform=self.platform)
        workspace = load_or_create_workspace(
            self.catalog_path,
            platform=self.platform,
            source_url=capture.url,
        )
        workspace.source_url = capture.url
        merge_discovery(workspace, result)
        save_workspace(workspace, self.catalog_path)
        self._json_response(
            200,
            {
                "ok": True,
                "page_type": result.page_type.value,
                "candidates": [item.model_dump(mode="json") for item in result.candidates],
                "warnings": result.warnings,
            },
        )
        _log(
            "Listing classified as "
            f"{result.page_type.value}; candidates discovered: {len(result.candidates)}"
        )

    def _sync_detail(self, raw: Any) -> None:
        submission = ProgramDetailSubmission.model_validate(raw)
        workspace = load_or_create_workspace(
            self.catalog_path,
            platform=self.platform,
            source_url=submission.capture.url,
        )
        known = {entry.candidate.id for entry in workspace.programs}
        if submission.candidate.id not in known:
            raise ValueError("candidate was not discovered in the current workspace")
        program = sync_program_capture(
            workspace,
            candidate_id=submission.candidate.id,
            capture=submission.capture,
            catalog_path=self.catalog_path,
            captures_dir=self.captures_dir,
            programs_dir=self.programs_dir,
        )
        allowed_scope = len(program.allowed_scope())
        denied_scope = len(program.denied_scope())
        review_issues = len(program.issues)
        self._json_response(
            200,
            {
                "ok": True,
                "program_id": program.id,
                "status": program.status.value,
                "allowed_scope": allowed_scope,
                "denied_scope": denied_scope,
                "review_issues": review_issues,
            },
        )
        _log(
            f"Synced {submission.candidate.name}: status={program.status.value}, "
            f"allow={allowed_scope}, deny={denied_scope}, review={review_issues}"
        )

    def _json_response(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type, X-ASTP-Intake-Token",
        )
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")

    def log_message(self, format: str, *args: object) -> None:
        return


def _handler(
    *,
    intake_token: str,
    platform: str,
    latest_capture_path: Path,
    catalog_path: Path,
    captures_dir: Path,
    programs_dir: Path,
) -> type[_ProgramIntakeHandler]:
    class Handler(_ProgramIntakeHandler):
        pass

    Handler.intake_token = intake_token
    Handler.platform = platform
    Handler.latest_capture_path = latest_capture_path
    Handler.catalog_path = catalog_path
    Handler.captures_dir = captures_dir
    Handler.programs_dir = programs_dir
    return Handler


def create_program_intake_server(
    *,
    intake_token: str,
    platform: str,
    latest_capture_path: Path,
    catalog_path: Path,
    captures_dir: Path,
    programs_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("authenticated browser intake must bind to loopback only")
    handler = _handler(
        intake_token=intake_token,
        platform=platform,
        latest_capture_path=latest_capture_path,
        catalog_path=catalog_path,
        captures_dir=captures_dir,
        programs_dir=programs_dir,
    )
    return ThreadingHTTPServer((host, port), handler)


def serve_program_intake(
    *,
    intake_token: str,
    platform: str,
    latest_capture_path: Path,
    catalog_path: Path,
    captures_dir: Path,
    programs_dir: Path,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    server = create_program_intake_server(
        intake_token=intake_token,
        platform=platform,
        latest_capture_path=latest_capture_path,
        catalog_path=catalog_path,
        captures_dir=captures_dir,
        programs_dir=programs_dir,
        host=host,
        port=port,
    )
    _log("Program intake protocol ready: " f"v{PROGRAM_INTAKE_PROTOCOL_VERSION} ({platform})")
    server.serve_forever()
