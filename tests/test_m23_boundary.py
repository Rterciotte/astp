from __future__ import annotations

import threading
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request

import pytest

from astp.authorization import AuthorizationRequest
from astp.evidence_bundle import export_evidence_bundle, verify_evidence_bundle
from astp.evidence_store import register_evidence
from astp.models import (
    Constraints,
    Decision,
    Engagement,
    MethodPolicy,
    RedactionProfile,
    RiskClass,
    ScopeKind,
    ScopePolicy,
    ScopeRule,
)
from astp.models import (
    TestDefinition as SecurityTestDefinition,
)
from astp.observation import observe_http
from astp.permits import issue_execution_permit
from astp.transport import PinnedObservationTransport, ResolvedEndpoint, TransportResponse

KEY = "0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def _test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="observation.http",
        title="Observation",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
    )


def _engagement(hostname: str = "example.test") -> Engagement:
    return Engagement(
        id="m23",
        name="M2.3",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value=hostname)]),
        methods=MethodPolicy(
            passive=Decision.ALLOW,
            safe_active=Decision.ALLOW,
            state_changing=Decision.APPROVAL_REQUIRED,
            intrusive=Decision.DENY,
        ),
        constraints=Constraints(
            max_requests_per_second=2,
            redaction=RedactionProfile(
                sensitive_headers={"x-private-note"},
                sensitive_query_parameters={"customer_ref"},
                sensitive_body_fields={"internal_code"},
            ),
        ),
    )


def _permit(engagement: Engagement, target: str):
    test = _test()
    permit = issue_execution_permit(
        engagement,
        test,
        AuthorizationRequest(
            target=target,
            http_method="GET",
            requested_requests_per_second=1,
        ),
        KEY,
        now=NOW,
    )
    return test, permit


def _paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "state_path": tmp_path / "state.json",
        "audit_path": tmp_path / "audit.jsonl",
        "evidence_path": tmp_path / "evidence.json",
        "manifest_path": tmp_path / "manifest.jsonl",
        "rate_state_path": tmp_path / "rate.json",
    }


@dataclass
class _FakeResponse:
    code: int = 200
    reason: str = "OK"

    @property
    def headers(self):
        return {
            "Content-Type": "application/json",
            "X-Private-Note": "do-not-store",
            "Location": "/next?customer_ref=ABC-123",
        }

    def getcode(self) -> int:
        return self.code

    def read(self, amount: int) -> bytes:
        return b'{"internal_code":"secret-value","public":"ok"}'[:amount]

    def close(self) -> None:
        return None


class _FakeRedirectTransport:
    def open(self, request: Request, *, timeout: float) -> TransportResponse:
        return TransportResponse(
            response=_FakeResponse(code=302, reason="Found"),
            resolved_endpoint=ResolvedEndpoint(
                hostname="example.test",
                port=443,
                addresses=("203.0.113.10",),
                connected_address="203.0.113.10",
            ),
        )


def test_engagement_redaction_profile_applies_to_evidence(tmp_path: Path) -> None:
    target = "https://example.test/data?customer_ref=ABC-123"
    engagement = _engagement()
    test, permit = _permit(engagement, target)
    result = observe_http(
        permit,
        engagement,
        test,
        KEY,
        target=target,
        method="GET",
        identity=None,
        requested_rps=1,
        now=NOW,
        transport=_FakeRedirectTransport(),
        **_paths(tmp_path),
    )
    evidence = result.evidence
    assert "ABC-123" not in evidence.target
    assert evidence.response_headers["X-Private-Note"] == "[REDACTED]"
    assert evidence.body_preview is not None
    assert "secret-value" not in evidence.body_preview
    assert "[REDACTED]" in evidence.body_preview


def test_redirect_is_new_action_even_when_same_origin(tmp_path: Path) -> None:
    target = "https://example.test/data"
    engagement = _engagement()
    test, permit = _permit(engagement, target)
    result = observe_http(
        permit,
        engagement,
        test,
        KEY,
        target=target,
        method="GET",
        identity=None,
        requested_rps=1,
        now=NOW,
        transport=_FakeRedirectTransport(),
        **_paths(tmp_path),
    )
    redirect = result.evidence.redirect
    assert redirect is not None
    assert redirect.same_origin is True
    assert redirect.in_scope is True
    assert redirect.requires_new_permit is True
    assert redirect.followed is False


@pytest.fixture
def local_http_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_pinned_transport_connects_to_pre_resolved_address(local_http_server) -> None:
    port = local_http_server.server_address[1]
    request = Request(f"http://localhost:{port}/", method="GET")
    result = PinnedObservationTransport().open(request, timeout=2)
    try:
        assert result.resolved_endpoint.connected_address in result.resolved_endpoint.addresses
        assert result.response.getcode() == 200
    finally:
        result.response.close()


def test_evidence_bundle_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.json"
    artifact.write_text('{"status": 200}\n', encoding="utf-8")
    manifest = tmp_path / "manifest.jsonl"
    register_evidence(
        manifest,
        artifact,
        evidence_type="http.observation",
        evidence_id="evidence-1",
        now=NOW,
    )
    bundle = tmp_path / "bundle.zip"
    receipt = export_evidence_bundle(manifest, bundle, now=NOW)
    assert len(receipt.artifacts) == 1
    valid, message = verify_evidence_bundle(bundle)
    assert valid is True
    assert "1 artifacts" in message

    tampered = tmp_path / "tampered.zip"
    with zipfile.ZipFile(bundle, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            payload = source.read(name)
            if name.startswith("artifacts/"):
                payload = b"tampered"
            target.writestr(name, payload)
    valid, message = verify_evidence_bundle(tampered)
    assert valid is False
    assert "artifact hash mismatch" in message.lower()


def test_evidence_bundle_receipt_detects_manifest_tampering(tmp_path: Path) -> None:
    artifact = tmp_path / "evidence.json"
    artifact.write_text("{}\n", encoding="utf-8")
    manifest = tmp_path / "manifest.jsonl"
    register_evidence(manifest, artifact, evidence_type="http.observation", now=NOW)
    bundle = tmp_path / "bundle.zip"
    export_evidence_bundle(manifest, bundle, now=NOW)

    tampered = tmp_path / "manifest-tampered.zip"
    with zipfile.ZipFile(bundle, "r") as source, zipfile.ZipFile(tampered, "w") as target:
        for name in source.namelist():
            payload = source.read(name)
            if name == "manifest.jsonl":
                payload += b"{}\n"
            target.writestr(name, payload)
    valid, message = verify_evidence_bundle(tampered)
    assert valid is False
    assert "manifest hash mismatch" in message.lower()
