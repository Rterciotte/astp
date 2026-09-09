from __future__ import annotations

import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

import pytest
from pydantic import ValidationError

from astp.counting_proxy import CountingProxy, RunningCountingProxy
from astp.detector_execution import (
    DetectorAccounting,
    DetectorExecutionRequest,
    DetectorExecutionService,
    DetectorRunStatus,
)
from astp.detector_policy import DetectorPolicyContext, MentionDisposition, decide_detector
from astp.detector_registry import builtin_detector_registry
from astp.detector_run_permit import DetectorRunPermitPayload, issue_detector_run_permit
from astp.evidence_store import verify_evidence_manifest
from astp.field_http_observation import (
    FieldHttpObservationAdapter,
    FieldHttpObservationConfig,
)
from astp.orchestrator_scheduler import rank_opportunity

KEY = "field-observation-test-signing-key"


class TargetHandler(BaseHTTPRequestHandler):
    hits: ClassVar[list[tuple[str, str, str | None]]] = []

    def log_message(self, *_args: object) -> None:
        return

    def _handle(self) -> None:
        self.__class__.hits.append((self.command, self.path, self.headers.get("User-Agent")))
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
        if self.path == "/slow":
            time.sleep(0.2)
        body = b"field observation"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "session=must-not-persist")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _handle
    do_HEAD = _handle


@pytest.fixture
def target():
    TargetHandler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _permit(target: str, *, methods=("GET", "HEAD"), requests=5, rps=100):
    now = datetime.now(UTC)
    return issue_detector_run_permit(
        DetectorRunPermitPayload(
            permit_id="permit-field",
            campaign_id="campaign-field",
            program_id="program-field",
            program_revision="revision-field",
            detector_id="astp.http-observation-field.v1",
            operation="http.observation.field",
            allowed_origin=target,
            allowed_path_prefix="/",
            allowed_methods=methods,
            max_requests=requests,
            max_concurrency=1,
            max_rps=rps,
            issued_at=now,
            expires_at=now + timedelta(minutes=2),
            policy_digest="policy",
            semantic_review_digest="semantic",
            action_id="action-field",
            detector_run_id="detector-run-field",
        ),
        KEY,
    )


def _request(target: str, **changes) -> DetectorExecutionRequest:
    detector = next(
        row
        for row in builtin_detector_registry()
        if row.detector_id == "astp.http-observation-field.v1"
    )
    context = DetectorPolicyContext(
        disposition=MentionDisposition.EXPLICITLY_ALLOWED,
        target_in_scope=True,
        remaining_requests=30,
    )
    opportunity = rank_opportunity(
        detector,
        program_id="program-field",
        target=target,
        signals=("authorized-passive-observation",),
        decision=decide_detector(detector, context),
        remaining_budget=30,
    )
    values = {
        "campaign_id": "campaign-field",
        "campaign_active": True,
        "program_id": "program-field",
        "program_revision": "revision-field",
        "current_program_revision": "revision-field",
        "target": target,
        "opportunity": opportunity,
        "detector": detector,
        "runtime_id": "counting-proxy",
        "runtime_digest": "sha256:proxy",
        "runtime_qualification_digest": "sha256:proxy",
        "lease_current": True,
        "target_in_scope": True,
        "semantic_review_complete": True,
        "policy_context": context,
        "global_remaining": 30,
        "program_remaining": 30,
        "detector_remaining": 30,
        "max_rps": 1,
        "proof_requirement": detector.proof_requirement,
        "user_agent": "Bughunt - Security Research",
        "authorized_path_prefix": "/",
    }
    values.update(changes)
    return DetectorExecutionRequest(**values)


def _local_adapter() -> FieldHttpObservationAdapter:
    return FieldHttpObservationAdapter(
        FieldHttpObservationConfig(target_network="local-only", proxy_image_digest="sha256:proxy"),
        KEY,
    )


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_get_and_head_traverse_counting_proxy(target, tmp_path, method) -> None:
    ledger = tmp_path / f"{method}.db"
    with RunningCountingProxy(CountingProxy(_permit(target), KEY, ledger)) as proxy:
        port = int(proxy.url.rsplit(":", 1)[1])
        receipt = _local_adapter()._observe(port, _request(target, http_method=method))
    assert receipt["status"] == 200
    assert TargetHandler.hits == [(method, "/", "Bughunt - Security Research")]
    assert (
        CountingProxy(_permit(target), KEY, ledger).accounting.summary()["responses_received"] == 1
    )


def test_post_is_rejected_by_typed_request(target) -> None:
    with pytest.raises(ValidationError):
        _request(target, http_method="POST")


def test_out_of_scope_redirect_is_observed_but_never_followed(target, tmp_path) -> None:
    ledger = tmp_path / "redirect-out.db"
    with RunningCountingProxy(CountingProxy(_permit(target), KEY, ledger)) as proxy:
        receipt = _local_adapter()._observe(
            int(proxy.url.rsplit(":", 1)[1]),
            _request(target + "/redirect-out", follow_redirects=True, max_redirects=2),
        )
    assert receipt["status"] == 403
    assert receipt["redirects"] == [
        {
            "target": "http://outside.invalid/collect",
            "same_origin": False,
            "followed": False,
            "reason": "out_of_scope",
        }
    ]
    assert len(TargetHandler.hits) == 1


def test_same_origin_redirect_is_followed_once_and_accounted(target, tmp_path) -> None:
    ledger = tmp_path / "redirect-in.db"
    with RunningCountingProxy(CountingProxy(_permit(target), KEY, ledger)) as proxy:
        receipt = _local_adapter()._observe(
            int(proxy.url.rsplit(":", 1)[1]),
            _request(target + "/redirect-in", follow_redirects=True, max_redirects=1),
        )
    assert receipt["status"] == 200
    assert [hit[1] for hit in TargetHandler.hits] == ["/redirect-in", "/final"]
    assert receipt["redirects"][0]["followed"]
    assert FieldHttpObservationAdapter._origin(receipt["final_url"]) == (
        "http",
        "127.0.0.1",
        int(target.rsplit(":", 1)[1]),
    )


def test_budget_and_rate_are_authoritative_in_proxy(target, tmp_path) -> None:
    ledger = tmp_path / "budget.db"
    proxy = CountingProxy(_permit(target, requests=1, rps=10), KEY, ledger)
    assert proxy.forward("GET", target, {}, b"")[0] == 200
    assert proxy.forward("GET", target, {}, b"")[0] == 429
    assert proxy.accounting.summary() == {
        "requests_attempted": 2,
        "requests_forwarded": 1,
        "responses_received": 1,
        "requests_blocked_before_io": 1,
        "requests_failed_after_io": 0,
        "request_bytes": 0,
        "response_bytes": 17,
    }

    rate_proxy = CountingProxy(_permit(target, requests=2, rps=1), KEY, tmp_path / "rate.db")
    started = time.monotonic()
    assert rate_proxy.forward("GET", target, {}, b"")[0] == 200
    assert rate_proxy.forward("GET", target, {}, b"")[0] == 200
    assert time.monotonic() - started >= 0.9


def test_proxy_digest_mismatch_and_stale_revision_block_before_io(
    target, tmp_path, monkeypatch
) -> None:
    adapter = _local_adapter()
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "sha256:different\n", "")

    monkeypatch.setattr(adapter, "_run", fake_run)
    service = DetectorExecutionService(tmp_path / "digest", KEY, (adapter,))
    digest_result = service.execute(_request(target))
    assert digest_result.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert digest_result.failure_category == "proxy_image_identity_drift"
    assert digest_result.accounting.forwarded == 0
    assert len(calls) == 1

    stale = DetectorExecutionService(tmp_path / "stale", KEY, (adapter,)).execute(
        _request(target, current_program_revision="changed")
    )
    assert stale.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert stale.authorization is None
    assert len(calls) == 1


def test_required_user_agent_and_sensitive_headers_are_not_persisted(target, tmp_path) -> None:
    adapter = _local_adapter()
    with RunningCountingProxy(
        CountingProxy(_permit(target), KEY, tmp_path / "headers.db")
    ) as proxy:
        receipt = adapter._observe(int(proxy.url.rsplit(":", 1)[1]), _request(target))
    run_root = tmp_path / "run"
    run_root.mkdir()
    evidence = adapter._persist_evidence(run_root, _request(target), _permit(target), receipt)
    assert TargetHandler.hits[0][2] == "Bughunt - Security Research"
    assert evidence.response_headers["Set-Cookie"] == "[REDACTED]"
    assert "must-not-persist" not in (run_root / "observation-evidence.json").read_text()
    assert "must-not-persist" not in (run_root / "observation-receipt.json").read_text()
    assert verify_evidence_manifest(run_root / "evidence-manifest.jsonl")[0]


def test_forwarding_ledger_state_is_unknown_and_no_direct_fallback(target, tmp_path) -> None:
    ledger = tmp_path / "unknown.db"
    proxy = CountingProxy(_permit(target), KEY, ledger)
    proxy.accounting.start(
        "request-unknown",
        "permit-field",
        "detector-run-field",
        "GET",
        target,
        "forwarding",
    )
    accounting = FieldHttpObservationAdapter.__dict__["execute"]  # prove adapter exists
    assert accounting is not None
    summary = __import__(
        "astp.docker_detector_adapter", fromlist=["DockerDetectorAdapter"]
    ).DockerDetectorAdapter._accounting(ledger)
    assert summary == DetectorAccounting(attempted=1, forwarded=1, unknown_outcomes=1)

    with pytest.raises(OSError):
        _local_adapter()._observe(1, _request(target))
    assert TargetHandler.hits == []


def test_concurrency_one_blocks_second_request(target, tmp_path) -> None:
    proxy = CountingProxy(_permit(target, requests=2), KEY, tmp_path / "concurrency.db")
    results = []
    first = threading.Thread(
        target=lambda: results.append(proxy.forward("GET", target + "/slow", {}, b"")[0])
    )
    first.start()
    time.sleep(0.05)
    results.append(proxy.forward("GET", target + "/slow", {}, b"")[0])
    first.join(timeout=2)
    assert sorted(results) == [200, 429]


def test_missing_authorization_is_rejected_before_adapter(target, tmp_path) -> None:
    adapter = _local_adapter()
    service = DetectorExecutionService(tmp_path, KEY, ())
    result = service.execute(_request(target))
    assert result.status is DetectorRunStatus.BLOCKED_BEFORE_IO
    assert result.authorization is None
    assert adapter.detector_ids == frozenset({"astp.http-observation-field.v1"})
