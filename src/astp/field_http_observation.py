from __future__ import annotations

import hashlib
import http.client
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from astp.detector_execution import (
    DetectorAdapterError,
    DetectorAdapterResult,
    DetectorArtifacts,
    DetectorExecutionRequest,
)
from astp.detector_run_permit import SignedDetectorRunPermit
from astp.docker_detector_adapter import DockerDetectorAdapter
from astp.evidence_store import SensitivityLabel, register_evidence
from astp.observation import (
    BodyArtifactReference,
    BoundaryDecision,
    HttpObservationEvidence,
    HttpResponseHop,
    RedirectObservation,
    ResponseProvenance,
    ResponseProvenanceSource,
    _decode_preview,
    _evidence_hash,
    _redact_headers,
    _write_body_artifact,
    _write_evidence,
    redact_url,
)
from astp.proof_model import ProofStateV2


class FieldHttpObservationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    target_network: str
    proxy_image: str = "astp/counting-proxy:m52"
    proxy_image_digest: str
    timeout_seconds: int = Field(default=15, ge=1, le=30)


class FieldHttpObservationAdapter:
    """GET/HEAD bridge with no target transport other than the verified proxy."""

    detector_ids = frozenset({"astp.http-observation-field.v1"})

    def __init__(self, config: FieldHttpObservationConfig, signing_key: str) -> None:
        self.config = config
        self.signing_key = signing_key

    @staticmethod
    def _run(argv: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)

    def _checked(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        completed = self._run(argv)
        if completed.returncode:
            raise DetectorAdapterError(
                "docker_control_failure", retryable=False, blocked_before_io=True
            )
        return completed

    def execute(
        self,
        request: DetectorExecutionRequest,
        permit: SignedDetectorRunPermit,
        run_root: Path,
    ) -> DetectorAdapterResult:
        if request.http_method not in {"GET", "HEAD"}:
            raise DetectorAdapterError(
                "http_method_rejected", retryable=False, blocked_before_io=True
            )
        if not request.user_agent:
            raise DetectorAdapterError(
                "required_user_agent_missing", retryable=False, blocked_before_io=True
            )
        inspected = self._run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", self.config.proxy_image]
        )
        if inspected.returncode or inspected.stdout.strip() != self.config.proxy_image_digest:
            raise DetectorAdapterError(
                "proxy_image_identity_drift", retryable=False, blocked_before_io=True
            )

        suffix = permit.payload.detector_run_id.removeprefix("detector-run-")
        worker_network = f"astp-field-worker-{suffix}"
        proxy_name = f"astp-field-proxy-{suffix}"
        ledger_path = run_root / "proxy-ledger.db"
        authorization_path = run_root / "authorization.json"
        self._checked(["docker", "network", "create", "--internal", worker_network])
        try:
            self._checked(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--name",
                    proxy_name,
                    "--network",
                    worker_network,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--publish",
                    "127.0.0.1::8081",
                    "--env",
                    f"ASTP_DETECTOR_RUN_KEY={self.signing_key}",
                    "--mount",
                    f"type=bind,src={authorization_path.resolve()},dst=/run/astp/permit.json,readonly",
                    "--mount",
                    f"type=bind,src={run_root.resolve()},dst=/var/lib/astp",
                    self.config.proxy_image,
                ]
            )
            self._checked(["docker", "network", "connect", self.config.target_network, proxy_name])
            self._wait_proxy_ready(proxy_name)
            proxy_port = self._proxy_port(proxy_name)
            receipt = self._observe(proxy_port, request)
            accounting = DockerDetectorAdapter._accounting(ledger_path)
            (run_root / "proxy-ledger-summary.json").write_text(
                accounting.model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
            evidence = self._persist_evidence(run_root, request, permit, receipt)
            public_receipt = {
                key: value for key, value in receipt.items() if key not in {"body", "headers"}
            }
            public_receipt["headers"] = _redact_headers(receipt["headers"])
            return DetectorAdapterResult(
                accounting=accounting,
                artifacts=DetectorArtifacts(
                    worker_receipt=public_receipt,
                    raw_output_path=str(run_root / "observation-evidence.json"),
                    evidence_ids=(evidence.evidence_id,),
                ),
                proof_state=ProofStateV2.OBSERVED,
                requirement_satisfied=True,
                network_started=accounting.forwarded > 0,
            )
        except (OSError, http.client.HTTPException) as exc:
            logs = self._run(["docker", "logs", proxy_name])
            (run_root / "proxy-stdout.txt").write_text(logs.stdout, encoding="utf-8")
            (run_root / "proxy-stderr.txt").write_text(logs.stderr, encoding="utf-8")
            (run_root / "transport-error.txt").write_text(
                f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
            )
            accounting = DockerDetectorAdapter._accounting(ledger_path)
            raise DetectorAdapterError(
                "observation_transport_failure",
                accounting=accounting,
                network_started=accounting.forwarded > 0,
                retryable=accounting.forwarded == 0,
            ) from exc
        finally:
            self._run(["docker", "rm", "--force", proxy_name])
            self._run(["docker", "network", "rm", worker_network])

    def _proxy_port(self, proxy_name: str) -> int:
        for _ in range(20):
            completed = self._run(["docker", "port", proxy_name, "8081/tcp"])
            if completed.returncode == 0 and completed.stdout.strip():
                return int(completed.stdout.strip().rsplit(":", 1)[1])
            time.sleep(0.1)
        raise DetectorAdapterError("proxy_unavailable", retryable=False, blocked_before_io=True)

    def _wait_proxy_ready(self, proxy_name: str) -> None:
        probe = "import socket; " "s=socket.create_connection(('127.0.0.1',8081),1); " "s.close()"
        for attempt in range(20):
            completed = self._run(["docker", "exec", proxy_name, "python", "-c", probe])
            if completed.returncode == 0:
                return
            if attempt == 19:
                raise DetectorAdapterError(
                    "proxy_unavailable", retryable=False, blocked_before_io=True
                )
            time.sleep(0.1)

    def _observe(self, proxy_port: int, request: DetectorExecutionRequest) -> dict:
        current = request.target
        redirects = []
        response_body = b""
        response_headers: dict[str, str] = {}
        response_chain: list[dict] = []
        status = 0
        request_id = ""
        for redirect_index in range(request.max_redirects + 1):
            connection = self._connect_proxy(proxy_port)
            connection.request(
                request.http_method,
                current,
                headers={"User-Agent": request.user_agent, "Connection": "close"},
            )
            response = connection.getresponse()
            response_body = response.read(request.max_body_bytes + 1)
            response_headers = dict(response.getheaders())
            status = response.status
            request_id = response_headers.get("X-ASTP-Request-ID", "")
            blocked_target = response_headers.get("X-ASTP-Redirect-Target")
            target_observed = response_headers.get("X-ASTP-Response-Provenance") == "target"
            target_headers = {
                name: value
                for name, value in response_headers.items()
                if not name.lower().startswith("x-astp-")
            }
            if target_observed:
                captured_body = response_body[: request.max_body_bytes]
                response_chain.append(
                    {
                        "target": current,
                        "status_code": status,
                        "headers": target_headers,
                        "body_sha256": hashlib.sha256(captured_body).hexdigest(),
                        "body_bytes_captured": len(captured_body),
                    }
                )
            location = blocked_target or response_headers.get("Location")
            if not location or not (300 <= status < 400 or blocked_target):
                break
            target = urljoin(current, location)
            same_origin = self._origin(target) == self._origin(request.target)
            followed = (
                request.follow_redirects
                and same_origin
                and redirect_index < request.max_redirects
                and not blocked_target
            )
            redirects.append(
                {
                    "target": target,
                    "same_origin": same_origin,
                    "followed": followed,
                    "reason": (
                        None if followed else "out_of_scope" if not same_origin else "bounded"
                    ),
                }
            )
            if not followed:
                break
            current = target
        return {
            "status": status,
            "final_url": current,
            "headers": response_headers,
            "body": response_body[: request.max_body_bytes],
            "body_truncated": len(response_body) > request.max_body_bytes,
            "redirects": redirects,
            "proxy_request_id": request_id,
            "observed_at": datetime.now(UTC),
            "response_chain": response_chain,
        }

    def _connect_proxy(self, proxy_port: int) -> http.client.HTTPConnection:
        for attempt in range(20):
            connection = http.client.HTTPConnection(
                "127.0.0.1", proxy_port, timeout=self.config.timeout_seconds
            )
            try:
                connection.connect()
                return connection
            except ConnectionRefusedError:
                connection.close()
                if attempt == 19:
                    raise
                time.sleep(0.1)
        raise AssertionError("unreachable")

    @staticmethod
    def _origin(target: str) -> tuple[str, str | None, int]:
        parsed = urlsplit(target)
        return (
            parsed.scheme,
            parsed.hostname,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        )

    @staticmethod
    def _persist_evidence(
        run_root: Path,
        request: DetectorExecutionRequest,
        permit: SignedDetectorRunPermit,
        receipt: dict,
    ) -> HttpObservationEvidence:
        body = receipt["body"]
        body_path = run_root / "observation.body.bin"
        if body:
            _write_body_artifact(body_path, body)
        body_reference = (
            BodyArtifactReference(
                path=str(body_path),
                sha256=hashlib.sha256(body).hexdigest(),
                size_bytes=len(body),
                sensitivity=SensitivityLabel.INTERNAL,
            )
            if body
            else None
        )
        redirects = receipt["redirects"]
        last_redirect = redirects[-1] if redirects else None
        raw_headers = receipt["headers"]
        provenance_value = raw_headers.get("X-ASTP-Response-Provenance")
        synthetic = raw_headers.get("X-ASTP-Response-Synthetic", "").lower() == "true"
        boundary_reason = raw_headers.get("X-ASTP-Boundary-Reason")
        target_observed = provenance_value == "target" and not synthetic
        provenance = ResponseProvenance(
            source=(
                ResponseProvenanceSource.TARGET
                if target_observed
                else ResponseProvenanceSource.ASTP_BOUNDARY
            ),
            target_response_observed=target_observed,
            synthetic=not target_observed,
            producer="target" if target_observed else "counting_proxy",
            reason=None if target_observed else boundary_reason or "boundary_response",
        )
        target_headers = {
            name: value
            for name, value in raw_headers.items()
            if not name.lower().startswith("x-astp-")
        }
        preliminary = HttpObservationEvidence(
            evidence_id=str(uuid4()),
            action_id=permit.payload.action_id,
            permit_id=permit.payload.permit_id,
            engagement_id=request.campaign_id,
            test_id=request.detector.operation,
            observed_at=receipt["observed_at"],
            method=request.http_method,
            target=redact_url(receipt["final_url"]),
            status_code=receipt["status"],
            response_headers=_redact_headers(target_headers) if target_observed else {},
            content_type=target_headers.get("Content-Type") if target_observed else None,
            body_bytes_captured=len(body),
            body_truncated=receipt["body_truncated"],
            body_sha256=hashlib.sha256(body).hexdigest(),
            body_preview=(
                _decode_preview(body, target_headers.get("Content-Type"))
                if target_observed
                else None
            ),
            body_artifact=body_reference,
            redirect=(
                RedirectObservation(
                    target=redact_url(last_redirect["target"]),
                    in_scope=last_redirect["same_origin"],
                    same_origin=last_redirect["same_origin"],
                    followed=last_redirect["followed"],
                )
                if last_redirect
                else None
            ),
            response_provenance=provenance,
            boundary=(
                BoundaryDecision(
                    producer="counting_proxy",
                    reason=boundary_reason,
                    redirect_followed=last_redirect["followed"] if last_redirect else None,
                )
                if boundary_reason
                else None
            ),
            response_chain=tuple(
                HttpResponseHop(
                    target=redact_url(hop["target"]),
                    status_code=hop["status_code"],
                    response_headers=_redact_headers(hop["headers"]),
                    body_sha256=hop["body_sha256"],
                    body_bytes_captured=hop["body_bytes_captured"],
                    provenance=ResponseProvenance(
                        source=ResponseProvenanceSource.TARGET,
                        target_response_observed=True,
                        synthetic=False,
                        producer="target",
                    ),
                )
                for hop in receipt.get("response_chain", [])
            ),
            evidence_hash="pending",
        )
        payload = preliminary.model_dump(mode="json", exclude={"evidence_hash"})
        evidence = preliminary.model_copy(update={"evidence_hash": _evidence_hash(payload)})
        evidence_path = run_root / "observation-evidence.json"
        manifest_path = run_root / "evidence-manifest.jsonl"
        _write_evidence(evidence_path, evidence)
        if body:
            register_evidence(
                manifest_path,
                body_path,
                evidence_type="http.observation.body",
                evidence_id=evidence.evidence_id,
                permit_id=permit.payload.permit_id,
                action_id=permit.payload.action_id,
            )
        register_evidence(
            manifest_path,
            evidence_path,
            evidence_type="http.observation",
            evidence_id=evidence.evidence_id,
            permit_id=permit.payload.permit_id,
            action_id=permit.payload.action_id,
        )
        (run_root / "observation-receipt.json").write_text(
            json.dumps(
                {
                    **{
                        key: value
                        for key, value in receipt.items()
                        if key not in {"body", "headers"}
                    },
                    "headers": _redact_headers(receipt["headers"]),
                    "response_chain": [
                        {**hop, "headers": _redact_headers(hop["headers"])}
                        for hop in receipt.get("response_chain", [])
                    ],
                    "observed_at": receipt["observed_at"].isoformat(),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return evidence
