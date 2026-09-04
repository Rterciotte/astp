from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from astp.authorization import AuthorizationRequest
from astp.lifecycle import permit_status, verify_audit_chain
from astp.models import (
    Constraints,
    Decision,
    Engagement,
    MethodPolicy,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as SecurityTestDefinition,
)
from astp.observation import (
    ObservationError,
    observe_http,
    verify_observation_evidence,
)
from astp.permits import issue_execution_permit

KEY = "0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


class _Handler(BaseHTTPRequestHandler):
    request_count = 0
    request_count_lock = threading.Lock()

    def do_GET(self) -> None:
        with self.request_count_lock:
            type(self).request_count += 1
        if self.path.startswith("/redirect-external"):
            self.send_response(302)
            self.send_header("Location", "https://outside.invalid/landing?token=secret")
            self.end_headers()
            return
        if self.path.startswith("/redirect-local"):
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
            return
        if self.path.startswith("/large"):
            body = b"x" * 100
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        body = b'{"token":"super-secret","message":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", "session=abc123")
        self.send_header("X-Test", "Bearer abc.def.ghi")
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:
        self.send_response(204)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def http_server():
    _Handler.request_count = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _engagement() -> Engagement:
    return Engagement(
        id="observation-example",
        name="Observation Example",
        scope=ScopePolicy(
            allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="127.0.0.1")],
            denied=[],
            approval_required=[],
        ),
        methods=MethodPolicy(
            passive=Decision.ALLOW,
            safe_active=Decision.ALLOW,
            state_changing=Decision.APPROVAL_REQUIRED,
            intrusive=Decision.DENY,
        ),
        constraints=Constraints(max_requests_per_second=5),
    )


def _test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="observation.http",
        title="Bounded HTTP observation",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
        required_context=[],
    )


def _permit(target: str, method: str = "GET"):
    engagement = _engagement()
    test = _test()
    permit = issue_execution_permit(
        engagement,
        test,
        AuthorizationRequest(
            target=target,
            http_method=method,
            requested_requests_per_second=1,
        ),
        KEY,
        now=NOW,
    )
    return engagement, test, permit


def _observe(
    tmp_path: Path,
    target: str,
    *,
    method: str = "GET",
    max_body_bytes: int = 262_144,
):
    engagement, test, permit = _permit(target, method)
    result = observe_http(
        permit,
        engagement,
        test,
        KEY,
        target=target,
        method=method,
        identity=None,
        requested_rps=1,
        state_path=tmp_path / "state.json",
        audit_path=tmp_path / "audit.jsonl",
        evidence_path=tmp_path / "evidence.json",
        manifest_path=tmp_path / "evidence-manifest.jsonl",
        rate_state_path=tmp_path / "rate-state.json",
        max_body_bytes=max_body_bytes,
        now=NOW,
    )
    return engagement, test, permit, result


def test_get_observation_consumes_permit_and_writes_redacted_evidence(
    tmp_path: Path, http_server: str
) -> None:
    target = f"{http_server}/data?token=query-secret&safe=value"
    _, _, permit, result = _observe(tmp_path, target)

    assert result.evidence.status_code == 200
    assert result.evidence.target.endswith("token=%5BREDACTED%5D&safe=value")
    assert result.evidence.response_headers["Set-Cookie"] == "[REDACTED]"
    assert "abc.def.ghi" not in result.evidence.response_headers["X-Test"]
    assert result.evidence.body_preview is not None
    assert "super-secret" not in result.evidence.body_preview
    assert result.evidence.evidence_hash
    assert result.evidence_path.exists()
    assert permit_status(tmp_path / "state.json", permit.payload.permit_id).value == "consumed"


def test_head_observation_captures_no_body(tmp_path: Path, http_server: str) -> None:
    _, _, _, result = _observe(tmp_path, f"{http_server}/head", method="HEAD")
    assert result.evidence.status_code == 204
    assert result.evidence.body_bytes_captured == 0
    assert result.evidence.body_sha256
    assert result.evidence.body_preview is None


def test_response_body_is_bounded_and_marked_truncated(tmp_path: Path, http_server: str) -> None:
    _, _, _, result = _observe(
        tmp_path,
        f"{http_server}/large",
        max_body_bytes=16,
    )
    assert result.evidence.body_bytes_captured == 16
    assert result.evidence.body_truncated is True


def test_external_redirect_is_recorded_but_never_followed(tmp_path: Path, http_server: str) -> None:
    _, _, _, result = _observe(tmp_path, f"{http_server}/redirect-external")
    assert result.evidence.status_code == 302
    assert result.evidence.redirect is not None
    assert result.evidence.redirect.followed is False
    assert result.evidence.redirect.in_scope is False
    assert "secret" not in result.evidence.redirect.target


def test_in_scope_redirect_is_still_not_followed(tmp_path: Path, http_server: str) -> None:
    _, _, _, result = _observe(tmp_path, f"{http_server}/redirect-local")
    assert result.evidence.status_code == 302
    assert result.evidence.redirect is not None
    assert result.evidence.redirect.followed is False
    assert result.evidence.redirect.in_scope is True


def test_replay_is_rejected_before_second_network_action(tmp_path: Path, http_server: str) -> None:
    target = f"{http_server}/data"
    engagement, test, permit = _permit(target)
    kwargs = {
        "target": target,
        "method": "GET",
        "identity": None,
        "requested_rps": 1,
        "state_path": tmp_path / "state.json",
        "audit_path": tmp_path / "audit.jsonl",
        "evidence_path": tmp_path / "evidence.json",
        "manifest_path": tmp_path / "evidence-manifest.jsonl",
        "rate_state_path": tmp_path / "rate-state.json",
        "now": NOW,
    }
    observe_http(permit, engagement, test, KEY, **kwargs)
    with pytest.raises(ObservationError, match="already been consumed"):
        observe_http(permit, engagement, test, KEY, **kwargs)


def test_post_is_rejected_without_consuming_permit(tmp_path: Path, http_server: str) -> None:
    target = f"{http_server}/data"
    engagement, test, permit = _permit(target, method="POST")
    with pytest.raises(ObservationError, match="only permits GET and HEAD"):
        observe_http(
            permit,
            engagement,
            test,
            KEY,
            target=target,
            method="POST",
            identity=None,
            requested_rps=1,
            state_path=tmp_path / "state.json",
            audit_path=tmp_path / "audit.jsonl",
            evidence_path=tmp_path / "evidence.json",
            manifest_path=tmp_path / "evidence-manifest.jsonl",
            rate_state_path=tmp_path / "rate-state.json",
            now=NOW,
        )
    assert permit_status(tmp_path / "state.json", permit.payload.permit_id).value == "available"


def test_evidence_file_matches_model_and_audit_chain_is_valid(
    tmp_path: Path, http_server: str
) -> None:
    _, _, _, result = _observe(tmp_path, f"{http_server}/data")
    stored = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert stored["evidence_hash"] == result.evidence.evidence_hash
    valid, message = verify_audit_chain(tmp_path / "audit.jsonl")
    assert valid is True
    assert "valid" in message.lower()


def test_evidence_hash_verification_detects_tampering(tmp_path: Path, http_server: str) -> None:
    _, _, _, result = _observe(tmp_path, f"{http_server}/data")
    assert verify_observation_evidence(result.evidence) is True
    tampered = result.evidence.model_copy(update={"status_code": 500})
    assert verify_observation_evidence(tampered) is False


def test_concurrent_replay_allows_only_one_network_request(
    tmp_path: Path, http_server: str
) -> None:
    target = f"{http_server}/data"
    engagement, test, permit = _permit(target)
    start_count = _Handler.request_count
    results: list[str] = []
    barrier = threading.Barrier(2)

    def run() -> None:
        barrier.wait()
        try:
            observe_http(
                permit,
                engagement,
                test,
                KEY,
                target=target,
                method="GET",
                identity=None,
                requested_rps=1,
                state_path=tmp_path / "state.json",
                audit_path=tmp_path / "audit.jsonl",
                evidence_path=tmp_path / f"evidence-{threading.get_ident()}.json",
                manifest_path=tmp_path / "evidence-manifest.jsonl",
                rate_state_path=tmp_path / "rate-state.json",
                now=NOW,
            )
            results.append("accepted")
        except ObservationError:
            results.append("rejected")

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert sorted(results) == ["accepted", "rejected"]
    assert _Handler.request_count - start_count == 1
    valid, _ = verify_audit_chain(tmp_path / "audit.jsonl")
    assert valid is True
