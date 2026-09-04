from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import Request

import pytest

from astp.authorization import AuthorizationRequest
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
from astp.observation import ObservationError, observe_http
from astp.permits import issue_execution_permit
from astp.transport import (
    ObservationTransportError,
    ResolvedEndpoint,
    TransportFailureKind,
    TransportResponse,
    resolve_endpoint,
)

KEY = "0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)


def _engagement() -> Engagement:
    return Engagement(
        id="m22",
        name="M2.2",
        scope=ScopePolicy(allowed=[ScopeRule(kind=ScopeKind.DOMAIN, value="example.test")]),
        methods=MethodPolicy(
            passive=Decision.ALLOW,
            safe_active=Decision.ALLOW,
            state_changing=Decision.APPROVAL_REQUIRED,
            intrusive=Decision.DENY,
        ),
        constraints=Constraints(max_requests_per_second=2),
    )


def _test() -> SecurityTestDefinition:
    return SecurityTestDefinition(
        id="observation.http",
        title="Observation",
        category="observation",
        risk_class=RiskClass.SAFE_ACTIVE,
    )


def _permit(target: str):
    engagement = _engagement()
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
    return engagement, test, permit


@dataclass
class _FakeResponse:
    code: int = 200
    reason: str = "OK"

    @property
    def headers(self):
        return {"Content-Type": "text/plain"}

    def getcode(self) -> int:
        return self.code

    def read(self, amount: int) -> bytes:
        return b"ok"[:amount]

    def close(self) -> None:
        return None


class _FakeTransport:
    def open(self, request: Request, *, timeout: float) -> TransportResponse:
        assert request.full_url == "https://example.test/data"
        assert timeout > 0
        return TransportResponse(
            response=_FakeResponse(),
            resolved_endpoint=ResolvedEndpoint(
                hostname="example.test",
                port=443,
                addresses=("203.0.113.10",),
            ),
        )


class _FailingTransport:
    def open(self, request: Request, *, timeout: float) -> TransportResponse:
        raise ObservationTransportError(TransportFailureKind.TLS, "TLS failed")


def _paths(tmp_path: Path) -> dict[str, Path]:
    return {
        "state_path": tmp_path / "state.json",
        "audit_path": tmp_path / "audit.jsonl",
        "evidence_path": tmp_path / "evidence.json",
        "manifest_path": tmp_path / "manifest.jsonl",
        "rate_state_path": tmp_path / "rate.json",
    }


def test_transport_metadata_is_recorded_in_evidence(tmp_path: Path) -> None:
    target = "https://example.test/data"
    engagement, test, permit = _permit(target)
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
        transport=_FakeTransport(),
        **_paths(tmp_path),
    )
    assert result.evidence.resolved_endpoint is not None
    assert result.evidence.resolved_endpoint.addresses == ("203.0.113.10",)


def test_transport_failure_writes_structured_failure_evidence(tmp_path: Path) -> None:
    target = "https://example.test/data"
    engagement, test, permit = _permit(target)
    paths = _paths(tmp_path)
    with pytest.raises(ObservationError, match="transport failed: tls"):
        observe_http(
            permit,
            engagement,
            test,
            KEY,
            target=target,
            method="GET",
            identity=None,
            requested_rps=1,
            now=NOW,
            transport=_FailingTransport(),
            **paths,
        )
    evidence = json.loads(paths["evidence_path"].read_text(encoding="utf-8"))
    assert evidence["failure_kind"] == "tls"
    assert evidence["target"] == target
    manifest = paths["manifest_path"].read_text(encoding="utf-8")
    assert "http.observation.failure" in manifest


def test_local_dns_resolution_is_deterministic_and_deduplicated() -> None:
    endpoint = resolve_endpoint("localhost", 80)
    assert endpoint.hostname == "localhost"
    assert endpoint.port == 80
    assert endpoint.addresses == tuple(sorted(set(endpoint.addresses)))
