import sqlite3
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection

import pytest

from astp.counting_proxy import CountingProxy, RunningCountingProxy
from astp.detector_run_permit import DetectorRunPermitPayload, issue_detector_run_permit
from astp.m52_acceptance_lab import LocalAcceptanceLab

KEY = "detector-run-test-key-that-is-long-enough"


def _permit(origin: str, **changes):
    now = datetime.now(UTC)
    values = {
        "permit_id": "permit-1",
        "campaign_id": "campaign-1",
        "program_id": "program-1",
        "program_revision": "revision-1",
        "detector_id": "ffuf.discovery-bounded.v1",
        "operation": "ffuf.discovery-bounded.v1",
        "allowed_origin": origin,
        "allowed_path_prefix": "/",
        "allowed_methods": ("GET",),
        "max_requests": 2,
        "max_concurrency": 1,
        "max_rps": 100,
        "issued_at": now,
        "expires_at": now + timedelta(minutes=2),
        "policy_digest": "policy-sha256",
        "semantic_review_digest": "semantic-sha256",
        "action_id": "action-1",
        "detector_run_id": "run-1",
    }
    values.update(changes)
    return issue_detector_run_permit(DetectorRunPermitPayload(**values), KEY)


def _proxy_get(proxy_url: str, target: str) -> tuple[int, bytes, str]:
    proxy = HTTPConnection(proxy_url.removeprefix("http://"), timeout=3)
    proxy.request("GET", target, headers={"Authorization": "Bearer never-log-this"})
    response = proxy.getresponse()
    return response.status, response.read(), response.getheader("X-ASTP-Request-ID")


def test_proxy_forwards_exact_origin_and_enforces_budget_before_io(tmp_path):
    with LocalAcceptanceLab() as lab:
        counting = CountingProxy(_permit(lab.base_url), KEY, tmp_path / "ledger.db")
        with RunningCountingProxy(counting) as proxy:
            first = _proxy_get(proxy.url, lab.base_url + "/.astp-hidden")
            second = _proxy_get(proxy.url, lab.base_url + "/health")
            blocked = _proxy_get(proxy.url, lab.base_url + "/third")
    assert first[0] == 200 and second[0] == 404 and blocked[0] == 429
    assert first[2] != second[2]
    assert counting.accounting.summary() == {
        "requests_attempted": 3,
        "requests_forwarded": 2,
        "responses_received": 2,
        "requests_blocked_before_io": 1,
        "requests_failed_after_io": 0,
        "request_bytes": 0,
        "response_bytes": 24,
    }
    assert "never-log-this" not in (tmp_path / "ledger.db").read_bytes().decode(errors="ignore")


def test_authoritative_forwarding_timestamps_include_rate_limit_wait(tmp_path):
    ledger = tmp_path / "rate-ledger.db"
    with LocalAcceptanceLab() as lab:
        counting = CountingProxy(_permit(lab.base_url, max_rps=4), KEY, ledger)
        with RunningCountingProxy(counting) as proxy:
            assert _proxy_get(proxy.url, lab.base_url + "/health")[0] == 404
            assert _proxy_get(proxy.url, lab.base_url + "/health")[0] == 404
    with sqlite3.connect(ledger) as db:
        timestamps = [
            datetime.fromisoformat(row[0])
            for row in db.execute("SELECT started_at FROM requests ORDER BY started_at")
        ]
    assert (timestamps[1] - timestamps[0]).total_seconds() >= 0.24


@pytest.mark.parametrize(
    "target",
    [
        "https://127.0.0.1:1/path",
        "http://127.0.0.1:1/path",
        "ftp://127.0.0.1/path",
    ],
)
def test_proxy_rejects_wrong_scheme_host_or_port_without_io(tmp_path, target):
    permit = _permit("http://example.test:8080")
    counting = CountingProxy(permit, KEY, tmp_path / "ledger.db")
    status, _, _, _ = counting.forward("GET", target, {}, b"")
    assert status == 403
    assert counting.accounting.summary()["requests_forwarded"] == 0


def test_proxy_path_prefix_requires_a_segment_boundary(tmp_path):
    permit = _permit("http://example.test", allowed_path_prefix="/api")
    counting = CountingProxy(permit, KEY, tmp_path / "ledger.db")
    status, _, _, _ = counting.forward("GET", "http://example.test/api-evil", {}, b"")
    assert status == 403
    assert counting.accounting.summary()["requests_forwarded"] == 0


@pytest.mark.parametrize("suffix", ["/api/../admin", "/api/%2e%2e/admin"])
def test_proxy_path_prefix_rejects_dot_segment_escape(tmp_path, suffix):
    permit = _permit("http://example.test", allowed_path_prefix="/api")
    counting = CountingProxy(permit, KEY, tmp_path / "ledger.db")
    status, _, _, _ = counting.forward("GET", "http://example.test" + suffix, {}, b"")
    assert status == 403
    assert counting.accounting.summary()["requests_forwarded"] == 0


def test_proxy_blocks_out_of_scope_redirect_and_connect(tmp_path):
    with LocalAcceptanceLab() as lab:
        counting = CountingProxy(_permit(lab.base_url), KEY, tmp_path / "ledger.db")
        with RunningCountingProxy(counting) as proxy:
            status, body, _ = _proxy_get(
                proxy.url, lab.base_url + "/redirect?next=http://outside.test/"
            )
            connection = HTTPConnection(proxy.url.removeprefix("http://"), timeout=3)
            connection.request("CONNECT", "outside.test:443")
            connect_status = connection.getresponse().status
    assert status == 302 and body == b""
    assert connect_status == 405


def test_expired_or_tampered_permit_never_starts_proxy(tmp_path):
    now = datetime.now(UTC)
    expired = _permit(
        "http://example.test",
        issued_at=now - timedelta(minutes=2),
        expires_at=now - timedelta(minutes=1),
    )
    with pytest.raises(ValueError, match="not currently valid"):
        CountingProxy(expired, KEY, tmp_path / "expired.db")
    with pytest.raises(ValueError, match="signature"):
        CountingProxy(
            expired.model_copy(update={"signature": "0" * 64}), KEY, tmp_path / "tampered.db"
        )


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("campaign_id", "wrong-campaign"),
        ("program_id", "wrong-program"),
        ("detector_id", "wrong-detector"),
    ],
)
def test_proxy_rejects_wrong_execution_context_binding(tmp_path, field, wrong):
    kwargs = {f"expected_{field}": wrong}
    with pytest.raises(ValueError, match="binding mismatch"):
        CountingProxy(_permit("http://example.test"), KEY, tmp_path / "ledger.db", **kwargs)
