from __future__ import annotations

import json
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar, Self
from urllib.parse import parse_qs, urlsplit


class VulnerableLabHandler(BaseHTTPRequestHandler):
    server_version = "ASTP-M52-Lab/1"
    sessions: ClassVar[set[str]] = set()
    oast_callbacks: ClassVar[set[str]] = set()
    rate_limit_requests: ClassVar[int] = 0

    def log_message(self, *_args: object) -> None:
        return

    def _send(
        self,
        body: str,
        status: int = 200,
        *,
        content_type: str = "text/html",
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/reflect":
            self._send(f"<p>{query.get('q',[''])[0]}</p>")
            return
        if parsed.path == "/dom":
            self._send("<script>sink.innerHTML=location.hash.slice(1)</script>")
            return
        if parsed.path == "/secret":
            self._send(
                json.dumps(
                    {"api_key": "AKIAABCDEFGHIJKLMNOP", "db": "postgres://user:pass@db/app"}
                ),
                content_type="application/json",
            )
            return
        if parsed.path == "/cve-fixture":
            self._send("fixture", headers={"X-ASTP-CVE-Fixture": "CVE-2099-0001-vulnerable"})
            return
        if parsed.path == "/slow":
            time.sleep(2)
            self._send("slow response")
            return
        if parsed.path in {"/idor/object/A", "/secure/object/A"}:
            identity = self.headers.get("X-ASTP-Identity", "")
            vulnerable = parsed.path.startswith("/idor/")
            if identity == "identity-a" or (vulnerable and identity == "identity-b"):
                self._send(
                    '{"id":"A","email":"owner@example.test"}', content_type="application/json"
                )
                return
            self._send('{"error":"forbidden"}', 403, content_type="application/json")
            return
        if parsed.path == "/sql":
            value = query.get("id", [""])[0]
            connection = sqlite3.connect(":memory:")
            try:
                row = connection.execute(f"SELECT 'record' WHERE 1 = {value}").fetchone()
                self._send(row[0] if row else "not found", 200 if row else 404)
            except sqlite3.Error as exc:
                self._send(f"SQL syntax error: {exc}", 500)
            finally:
                connection.close()
            return
        if parsed.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", query.get("next", ["/"])[0])
            self.end_headers()
            return
        if parsed.path == "/cors":
            origin = self.headers.get("Origin", "null")
            self._send(
                "cors",
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
            )
            return
        if parsed.path == "/ssrf":
            payload = query.get("payload", [""])[0]
            if payload:
                self.oast_callbacks.add(payload)
            self._send("queued")
            return
        if parsed.path == "/.astp-hidden":
            self._send("hidden endpoint")
            return
        if parsed.path == "/api":
            type(self).rate_limit_requests += 1
            if type(self).rate_limit_requests == 1:
                self._send("retry later", 429, headers={"Retry-After": "2"})
            else:
                self._send("recovered")
            return
        if parsed.path == "/session":
            token = self.headers.get("X-ASTP-Session", "")
            self._send(
                "active" if token in self.sessions else "invalid",
                200 if token in self.sessions else 401,
            )
            return
        self._send("not found", 404)

    def do_POST(self) -> None:
        if self.path == "/login":
            old = self.headers.get("X-ASTP-Session", "")
            token = "session-after-login"
            self.sessions.discard(old)
            self.sessions.add(token)
            self._send(json.dumps({"session_ref": token}), content_type="application/json")
            return
        if self.path == "/logout":
            self.sessions.discard(self.headers.get("X-ASTP-Session", ""))
            self._send("logged out")
            return
        self._send("not found", 404)


class LocalAcceptanceLab:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableLabHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self) -> Self:
        VulnerableLabHandler.rate_limit_requests = 0
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), VulnerableLabHandler).serve_forever()
