from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return

    def _respond(self) -> None:
        print(
            json.dumps(
                {
                    "method": self.command,
                    "path": self.path,
                    "user_agent": self.headers.get("User-Agent"),
                }
            ),
            flush=True,
        )
        if self.path == "/redirect-in":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", "http://outside.invalid/collect")
            self.end_headers()
            return
        body = b"ASTP field HTTP local acceptance"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "acceptance-secret=must-be-redacted")
        self.send_header("Cache-Control", "private, max-age=0")
        self.send_header("Access-Control-Allow-Origin", "https://allowed.example")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _respond
    do_HEAD = _respond

    def do_POST(self) -> None:
        print(json.dumps({"method": "POST", "path": self.path}), flush=True)
        self.send_response(500)
        self.end_headers()


ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
