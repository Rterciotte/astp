from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator


class BrowserCapture(BaseModel):
    schema_version: str = "1"
    url: str
    title: str = ""
    text: str
    tables: list[list[list[str]]] = Field(default_factory=list)
    links: list[dict[str, str]] = Field(default_factory=list)
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("url")
    @classmethod
    def require_http_url(cls, value: str) -> str:
        if not value.startswith(("http://", "https://")):
            raise ValueError("browser capture URL must be HTTP or HTTPS")
        return value


@dataclass(frozen=True)
class CaptureReceipt:
    path: Path
    sha256: str


def capture_digest(capture: BrowserCapture) -> str:
    payload = capture.model_dump(mode="json")
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def write_capture(capture: BrowserCapture, output: Path) -> CaptureReceipt:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = capture.model_dump(mode="json")
    output.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return CaptureReceipt(path=output, sha256=capture_digest(capture))


def load_capture(path: Path) -> BrowserCapture:
    return BrowserCapture.model_validate_json(path.read_text(encoding="utf-8"))


def capture_to_text(capture: BrowserCapture) -> str:
    parts = [capture.title, capture.text]
    for table in capture.tables:
        parts.extend(" | ".join(row) for row in table)
    return "\n".join(part for part in parts if part)


class _CaptureHandler(BaseHTTPRequestHandler):
    output_path: Path
    intake_token: str

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_POST(self) -> None:
        if self.path != "/v1/browser-capture":
            self.send_error(404)
            return
        if self.headers.get("X-ASTP-Intake-Token") != self.intake_token:
            self.send_error(403)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > 5_000_000:
            self.send_error(413)
            return
        try:
            raw: Any = json.loads(self.rfile.read(length).decode("utf-8"))
            capture = BrowserCapture.model_validate(raw)
            receipt = write_capture(capture, self.output_path)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_error(400, str(exc))
            return
        body = json.dumps({"ok": True, "sha256": receipt.sha256}).encode("utf-8")
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-ASTP-Intake-Token")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")

    def log_message(self, format: str, *args: object) -> None:
        return


def _capture_handler(output: Path, intake_token: str) -> type[_CaptureHandler]:
    class Handler(_CaptureHandler):
        pass

    Handler.output_path = output
    Handler.intake_token = intake_token
    return Handler


def serve_capture(
    output: Path,
    *,
    intake_token: str,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> None:
    if not intake_token:
        raise ValueError("intake token is required")
    handler = _capture_handler(output, intake_token)
    server = ThreadingHTTPServer((host, port), handler)
    server.serve_forever()
