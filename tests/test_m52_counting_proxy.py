import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from astp.counting_proxy import AcceptanceProxyFault, CountingProxy, RunningCountingProxy
from astp.detector_run_permit import DetectorRunPermitPayload, issue_detector_run_permit
from astp.m52_acceptance_lab import LocalAcceptanceLab

KEY = "detector-run-test-key-that-is-long-enough"


class CountingTargetHandler(BaseHTTPRequestHandler):
    hits = 0
    lock = threading.Lock()

    def log_message(self, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        with type(self).lock:
            type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


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
        "unknown_outcomes": 0,
        "request_bytes": 0,
        "response_bytes": 24,
    }
    assert "never-log-this" not in (tmp_path / "ledger.db").read_bytes().decode(errors="ignore")


@pytest.mark.parametrize(("ceiling", "contenders"), [(1, 2), (3, 8)])
def test_atomic_budget_reservation_matches_independent_target_oracle(tmp_path, ceiling, contenders):
    CountingTargetHandler.hits = 0
    target = ThreadingHTTPServer(("127.0.0.1", 0), CountingTargetHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    origin = f"http://127.0.0.1:{target.server_port}"
    counting = CountingProxy(
        _permit(origin, max_requests=ceiling, max_concurrency=contenders),
        KEY,
        tmp_path / f"atomic-{ceiling}.db",
    )
    barrier = threading.Barrier(contenders)

    def contender() -> tuple[int, str]:
        barrier.wait(timeout=3)
        status, _, request_id = _proxy_get(proxy.url, origin + "/count")
        return status, request_id

    try:
        with (
            RunningCountingProxy(counting) as proxy,
            ThreadPoolExecutor(max_workers=contenders) as pool,
        ):
            results = list(pool.map(lambda _index: contender(), range(contenders)))
    finally:
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=2)

    summary = counting.accounting.summary()
    assert [status for status, _ in results].count(200) == ceiling
    assert [status for status, _ in results].count(429) == contenders - ceiling
    assert len({request_id for _, request_id in results}) == contenders
    assert CountingTargetHandler.hits == ceiling
    assert summary["requests_attempted"] == contenders
    assert summary["requests_forwarded"] == ceiling
    assert summary["requests_blocked_before_io"] == contenders - ceiling
    assert summary["requests_attempted"] == (
        summary["requests_forwarded"] + summary["requests_blocked_before_io"]
    )
    assert (
        summary["responses_received"]
        + summary["requests_failed_after_io"]
        + summary["unknown_outcomes"]
        == summary["requests_forwarded"]
    )


def test_durable_reservation_is_visible_and_crash_before_io_is_not_forwarded(tmp_path):
    accounting = CountingProxy(
        _permit("http://example.test", max_requests=1, max_concurrency=2),
        KEY,
        tmp_path / "reservation.db",
    ).accounting
    assert (
        accounting.admit(
            "request-1",
            "permit-1",
            "run-1",
            "GET",
            "http://example.test/",
            max_requests=1,
            max_concurrency=2,
        )
        is None
    )
    assert (
        accounting.admit(
            "request-2",
            "permit-1",
            "run-1",
            "GET",
            "http://example.test/",
            max_requests=1,
            max_concurrency=2,
        )
        == "request budget exhausted"
    )
    assert accounting.summary()["requests_forwarded"] == 0
    assert accounting.summary()["requests_blocked_before_io"] == 2


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
    assert (timestamps[1] - timestamps[0]).total_seconds() >= 0.20


def test_target_retry_after_is_persisted_as_scheduler_input(tmp_path):
    ledger = tmp_path / "retry-ledger.db"
    with LocalAcceptanceLab() as lab:
        counting = CountingProxy(_permit(lab.base_url), KEY, ledger)
        with RunningCountingProxy(counting) as proxy:
            assert _proxy_get(proxy.url, lab.base_url + "/api")[0] == 429
    with sqlite3.connect(ledger) as db:
        status, detail = db.execute("SELECT status,detail FROM requests").fetchone()
    assert status == 429
    assert detail == "retry_after_seconds=2"


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


class InjectedProcessExit(BaseException):
    pass


@pytest.mark.parametrize(
    ("fault", "attempted", "forwarded", "unknown"),
    [
        (AcceptanceProxyFault.AFTER_WORKER_LAUNCH_BEFORE_FIRST_IO, 0, 0, 0),
        (AcceptanceProxyFault.AFTER_FIRST_PROXY_FORWARD, 1, 1, 1),
    ],
)
def test_acceptance_fault_boundaries_are_derived_from_proxy_ledger(
    tmp_path, monkeypatch, fault, attempted, forwarded, unknown
):
    ledger = tmp_path / f"{fault.value}.db"
    proxy = CountingProxy(_permit("http://example.test"), KEY, ledger, acceptance_fault=fault)
    monkeypatch.setattr(
        "astp.counting_proxy.os._exit", lambda _code: (_ for _ in ()).throw(InjectedProcessExit())
    )

    with pytest.raises(InjectedProcessExit):
        proxy.forward("GET", "http://example.test/", {}, b"")

    summary = proxy.accounting.summary()
    assert summary["requests_attempted"] == attempted
    assert summary["requests_forwarded"] == forwarded
    assert summary["unknown_outcomes"] == unknown
